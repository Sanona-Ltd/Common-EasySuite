<?php

namespace EasySuite\Common\Http\Middleware;

use Closure;
use EasySuite\Common\Oidc\LoginController;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Schützt das SaaS-Panel eines Systems. Für Browser-Sessions (Web-Routen): Der Claim `saas_admin`
 * stammt aus dem Login-Token, das nach MFA ausgestellt wurde (`acr=mfa`).
 * Nutzbar sowohl mit Bearer-Token (API) als auch mit Login-Session (UI).
 */
class RequireSaasAdmin
{
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->attributes->get(RequireToken::ATTRIBUTE);

        $isAdmin = $token
            ? ($token->isSaasAdmin() && $token->hasMfa())
            : ($request->hasSession()
                && $request->session()->get(LoginController::SESSION_SAAS_ADMIN) === true
                && $request->session()->get(LoginController::SESSION_MFA) === true);

        abort_unless($isAdmin, 403, 'SaaS admin access required.');

        return $next($request);
    }
}
