<?php

namespace EasySuite\Common\Http\Middleware;

use Closure;
use EasySuite\Common\Oidc\LoginController;
use EasySuite\Common\Oidc\RevokedSessions;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

/**
 * Für Browser-Routen: beendet die lokale Session, sobald ihre `sid` (Back-Channel-Logout,
 * Event `session.revoked`) oder ihr User (Event `user.disabled`) gesperrt wurde.
 */
class EnforceSession
{
    public function __construct(private readonly RevokedSessions $revoked) {}

    public function handle(Request $request, Closure $next): Response
    {
        if (! $request->hasSession()) {
            return $next($request);
        }

        $session = $request->session();
        $sid = $session->get(LoginController::SESSION_SID);

        if ($sid !== null || $session->has(LoginController::SESSION_SUB)) {
            $revoked = $this->revoked->isSessionRevoked($sid)
                || $this->revoked->isSubjectRevoked(
                    $session->get(LoginController::SESSION_SUB),
                    $session->get(LoginController::SESSION_LOGIN_AT)
                );

            if ($revoked) {
                Auth::guard(config('easysuite.login.guard'))->logout();
                $session->invalidate();
                $session->regenerateToken();

                return redirect()->route('easysuite.login');
            }
        }

        return $next($request);
    }
}
