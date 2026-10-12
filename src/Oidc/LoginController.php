<?php

namespace EasySuite\Common\Oidc;

use EasySuite\Common\Jwt\InvalidTokenException;
use EasySuite\Common\Jwt\Jwk;
use EasySuite\Common\Jwt\TokenVerifier;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;

class LoginController extends Controller
{
    public const SESSION_FLOW = 'easysuite.oidc';

    public const SESSION_SID = 'easysuite.sid';

    public const SESSION_SUB = 'easysuite.sub';

    public const SESSION_LOGIN_AT = 'easysuite.login_at';

    public const SESSION_SAAS_ADMIN = 'easysuite.saas_admin';

    public const SESSION_MFA = 'easysuite.mfa';

    public const SESSION_TOKENS = 'easysuite.tokens';

    /** Ziel für Laravels `Authenticate`-Middleware (Route `login`). */
    public function login(): RedirectResponse
    {
        return redirect()->route('easysuite.login');
    }

    public function redirect(Request $request, OidcClient $oidc): RedirectResponse
    {
        $state = Str::random(40);
        $nonce = Str::random(40);
        $verifier = Jwk::b64urlEncode(random_bytes(48));

        $request->session()->put(self::SESSION_FLOW, compact('state', 'nonce', 'verifier'));

        // Apps können Step-up verlangen: /auth/redirect?acr_values=mfa&max_age=900
        $extra = array_filter($request->only(['acr_values', 'max_age', 'prompt', 'login_hint']), fn ($v) => $v !== null && $v !== '');

        return redirect()->away($oidc->authorizationUrl(
            $state,
            $nonce,
            Jwk::b64urlEncode(hash('sha256', $verifier, true)),
            $extra
        ));
    }

    public function callback(Request $request, OidcClient $oidc, TokenVerifier $verifier): RedirectResponse
    {
        $flow = $request->session()->pull(self::SESSION_FLOW);

        abort_unless(
            is_array($flow) && hash_equals($flow['state'], (string) $request->query('state')),
            400,
            'Invalid login state.'
        );
        abort_if($request->query('error'), 403, (string) ($request->query('error_description') ?: $request->query('error')));
        abort_unless($request->query('code'), 400, 'Missing authorization code.');

        $leeway = config('easysuite.leeway');
        $clientId = config('easysuite.client_id');

        try {
            $tokens = $oidc->exchangeCode((string) $request->query('code'), $flow['verifier']);
            $access = $verifier->verify($tokens['access_token'], $oidc->issuer(), $oidc->jwksUri(), $clientId, $leeway);

            if (isset($tokens['id_token'])) {
                $id = $verifier->verify($tokens['id_token'], $oidc->issuer(), $oidc->jwksUri(), $clientId, $leeway);
                abort_unless(hash_equals($flow['nonce'], (string) $id->claim('nonce')), 400, 'Invalid nonce.');
            }
        } catch (InvalidTokenException $e) {
            abort(403, 'Login could not be verified.');
        }

        $profile = $oidc->userinfo($tokens['access_token']);
        abort_if(isset($profile['sub']) && $profile['sub'] !== $access->sub(), 403, 'Subject mismatch.');
        $profile = array_filter($profile + ['sub' => $access->sub(), 'email' => $access->claim('email'), 'name' => $access->claim('name')]);

        $user = app(config('easysuite.login.provisioner'))->resolve($profile, $access);

        Auth::guard(config('easysuite.login.guard'))->login($user);
        $request->session()->regenerate();
        $request->session()->put([
            self::SESSION_SID => $access->sid(),
            self::SESSION_SUB => $access->sub(),
            self::SESSION_LOGIN_AT => time(),
            self::SESSION_SAAS_ADMIN => $access->isSaasAdmin(),
            self::SESSION_MFA => $access->hasMfa(),
            self::SESSION_TOKENS => [
                'access_token' => $tokens['access_token'],
                'refresh_token' => $tokens['refresh_token'] ?? null,
                'expires_at' => $access->expiresAt(),
            ],
        ]);

        return redirect()->intended(config('easysuite.login.redirect_after_login'));
    }

    public function logout(Request $request, OidcClient $oidc): RedirectResponse
    {
        Auth::guard(config('easysuite.login.guard'))->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        $after = rtrim((string) config('easysuite.self.url'), '/').'/'.ltrim(config('easysuite.login.redirect_after_logout'), '/');

        try {
            $endSession = $oidc->endpoint('end_session_endpoint');
        } catch (\Throwable) {
            $endSession = null;
        }

        if (! $endSession) {
            return redirect($after);
        }

        return redirect()->away($endSession.'?'.http_build_query([
            'client_id' => config('easysuite.client_id'),
            'post_logout_redirect_uri' => $after,
        ]));
    }
}
