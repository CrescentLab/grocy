<?php

namespace Grocy\Services;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

class MicrosoftAuthService extends BaseService
{
	private ?Client $HttpClient = null;

	public function IsEnabled(): bool
	{
		return defined('GROCY_MICROSOFT_AUTH_ENABLED') && GROCY_MICROSOFT_AUTH_ENABLED === true;
	}

	public function BuildAuthorizeUrl(): string
	{
		if (!$this->IsEnabled())
		{
			throw new \Exception('Microsoft authentication is not enabled');
		}

		$state = bin2hex(random_bytes(16));
		$this->SetStateCookie($state);

		$query = [
			'client_id' => $this->GetRequiredSetting('MICROSOFT_AUTH_CLIENT_ID'),
			'response_type' => 'code',
			'redirect_uri' => $this->ResolveRedirectUri(),
			'response_mode' => 'query',
			'scope' => $this->GetRequiredSetting('MICROSOFT_AUTH_SCOPES'),
			'state' => $state,
			'prompt' => 'select_account'
		];

		return 'https://login.microsoftonline.com/' . urlencode($this->GetRequiredSetting('MICROSOFT_AUTH_TENANT_ID')) . '/oauth2/v2.0/authorize?' . http_build_query($query);
	}

	public function HandleCallback(string $code, string $state): array
	{
		if (!$this->ValidateState($state))
		{
			throw new \Exception('Invalid Microsoft authentication state');
		}

		$this->ClearStateCookie();

		$tokenEndpoint = 'https://login.microsoftonline.com/' . urlencode($this->GetRequiredSetting('MICROSOFT_AUTH_TENANT_ID')) . '/oauth2/v2.0/token';
		$clientId = $this->GetRequiredSetting('MICROSOFT_AUTH_CLIENT_ID');
		$clientSecret = $this->GetRequiredSetting('MICROSOFT_AUTH_CLIENT_SECRET');
		$redirectUri = $this->ResolveRedirectUri();

		try
		{
			$response = $this->GetHttpClient()->post($tokenEndpoint, [
				'form_params' => [
					'client_id' => $clientId,
					'client_secret' => $clientSecret,
					'code' => $code,
					'redirect_uri' => $redirectUri,
					'grant_type' => 'authorization_code'
				]
			]);
		}
		catch (GuzzleException $ex)
		{
			throw new \Exception('Unable to exchange Microsoft authorization code: ' . $ex->getMessage());
		}

		$tokenData = json_decode((string)$response->getBody(), true);
		if (!isset($tokenData['access_token']))
		{
			throw new \Exception('Microsoft token exchange did not return an access token');
		}

		$claims = $this->GetUserClaims($tokenData['access_token']);
		$username = $this->GetClaimValue($claims, ['preferred_username', 'email', 'userPrincipalName']);
		if (empty($username))
		{
			throw new \Exception('Microsoft account did not provide an email address');
		}

		$user = $this->FindUser($username);
		if ($user === null)
		{
			$user = UsersService::GetInstance()->CreateUser(
				$username,
				$this->GetClaimValue($claims, ['given_name', 'givenName']),
				$this->GetClaimValue($claims, ['family_name', 'surname', 'familyName']),
				bin2hex(random_bytes(16))
			);
		}
		else
		{
			$user->update([
				'first_name' => $this->GetClaimValue($claims, ['given_name', 'givenName']),
				'last_name' => $this->GetClaimValue($claims, ['family_name', 'surname', 'familyName'])
			]);
		}

		return [
			'user_id' => (int)$user->id,
			'username' => $username
		];
	}

	private function GetUserClaims(string $accessToken): array
	{
		try
		{
			$response = $this->GetHttpClient()->get('https://graph.microsoft.com/v1.0/me?$select=id,displayName,givenName,surname,mail,userPrincipalName', [
				'headers' => [
					'Authorization' => 'Bearer ' . $accessToken,
					'Accept' => 'application/json'
				]
			]);
		}
		catch (GuzzleException $ex)
		{
			throw new \Exception('Unable to load Microsoft profile: ' . $ex->getMessage());
		}

		$claims = json_decode((string)$response->getBody(), true);
		return is_array($claims) ? $claims : [];
	}

	private function FindUser(string $username): ?object
	{
		$normalizedUsername = strtolower($username);
		$users = $this->DB->users()->fetchAll();

		foreach ($users as $user)
		{
			if (strtolower($user->username) === $normalizedUsername)
			{
				return $user;
			}
		}

		return null;
	}

	private function ResolveRedirectUri(): string
	{
		if (defined('GROCY_MICROSOFT_AUTH_REDIRECT_URI') && !empty(GROCY_MICROSOFT_AUTH_REDIRECT_URI))
		{
			return GROCY_MICROSOFT_AUTH_REDIRECT_URI;
		}

		$baseUrl = rtrim(GROCY_BASE_URL, '/');
		return $baseUrl . '/login/microsoft/callback';
	}

	private function GetRequiredSetting(string $settingName): string
	{
		if (!defined('GROCY_' . $settingName))
		{
			throw new \Exception('Microsoft authentication setting ' . $settingName . ' is not configured');
		}

		$value = constant('GROCY_' . $settingName);
		if (empty($value))
		{
			throw new \Exception('Microsoft authentication setting ' . $settingName . ' must not be empty');
		}

		return (string)$value;
	}

	private function SetStateCookie(string $state): void
	{
		setcookie('grocy_microsoft_state', $state, time() + 600, '/');
	}

	private function ValidateState(string $state): bool
	{
		return isset($_COOKIE['grocy_microsoft_state']) && hash_equals($_COOKIE['grocy_microsoft_state'], $state);
	}

	private function ClearStateCookie(): void
	{
		setcookie('grocy_microsoft_state', '', time() - 3600, '/');
	}

	private function GetClaimValue(array $claims, array $claimNames): string
	{
		foreach ($claimNames as $claimName)
		{
			if (isset($claims[$claimName]) && !empty($claims[$claimName]))
			{
				return (string)$claims[$claimName];
			}
		}

		return '';
	}

	private function GetHttpClient(): Client
	{
		if ($this->HttpClient === null)
		{
			$this->HttpClient = new Client();
		}

		return $this->HttpClient;
	}
}
