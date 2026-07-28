<?php

namespace Grocy\Middleware;

use Grocy\Services\MicrosoftAuthService;
use Grocy\Services\SessionService;
use Psr\Http\Message\ServerRequestInterface as Request;

class MicrosoftAuthMiddleware extends AuthMiddleware
{
	protected function authenticate(Request $request)
	{
		$auth = new SessionAuthMiddleware($this->AppContainer, $this->ResponseFactory);
		return $auth->authenticate($request);
	}

	public static function ProcessLogin(array $postParams)
	{
		throw new \Exception('Microsoft authentication uses the OAuth callback flow');
	}

	public static function BeginLogin(): string
	{
		return MicrosoftAuthService::GetInstance()->BuildAuthorizeUrl();
	}

	public static function FinishLogin(string $code, string $state): array
	{
		$authData = MicrosoftAuthService::GetInstance()->HandleCallback($code, $state);
		$sessionKey = SessionService::GetInstance()->CreateSession($authData['user_id']);
		self::SetSessionCookie($sessionKey);
		return $authData;
	}
}
