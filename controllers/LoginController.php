<?php

namespace Grocy\Controllers;

use Grocy\Services\SessionService;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

class LoginController extends BaseController
{
	public function LoginPage(Request $request, Response $response, array $args)
	{
		return $this->RenderPage($response, 'login');
	}

	public function Logout(Request $request, Response $response, array $args)
	{
		SessionService::GetInstance()->RemoveSession($_COOKIE[SessionService::SESSION_COOKIE_NAME]);
		return $response->withRedirect($this->AppContainer->get('UrlManager')->ConstructUrl('/'));
	}

	public function ProcessLogin(Request $request, Response $response, array $args)
	{
		$authMiddlewareClass = GROCY_AUTH_CLASS;

		$postParams = $request->getParsedBody();
		if (isset($postParams['password_base64']))
		{
			$postParams['password'] = base64_decode($postParams['password_base64']);
		}
		unset($postParams['password_base64']);

		if ($authMiddlewareClass::ProcessLogin($postParams))
		{
			return $response->withRedirect($this->AppContainer->get('UrlManager')->ConstructUrl('/'));
		}
		else
		{
			return $response->withRedirect($this->AppContainer->get('UrlManager')->ConstructUrl('/login?invalid=true'));
		}
	}

	public function MicrosoftLogin(Request $request, Response $response, array $args)
	{
		if (!defined('GROCY_MICROSOFT_AUTH_ENABLED') || GROCY_MICROSOFT_AUTH_ENABLED !== true)
		{
			return $response->withRedirect($this->AppContainer->get('UrlManager')->ConstructUrl('/login'));
		}

		return $response->withRedirect(\Grocy\Middleware\MicrosoftAuthMiddleware::BeginLogin());
	}

	public function MicrosoftCallback(Request $request, Response $response, array $args)
	{
		$query = $request->getQueryParams();
		if (!isset($query['code'], $query['state']))
		{
			return $response->withRedirect($this->AppContainer->get('UrlManager')->ConstructUrl('/login?invalid=true'));
		}

		try
		{
			\Grocy\Middleware\MicrosoftAuthMiddleware::FinishLogin($query['code'], $query['state']);
			return $response->withRedirect($this->AppContainer->get('UrlManager')->ConstructUrl('/'));
		}
		catch (\Exception $ex)
		{
			return $response->withRedirect($this->AppContainer->get('UrlManager')->ConstructUrl('/login?invalid=true'));
		}
	}
}
