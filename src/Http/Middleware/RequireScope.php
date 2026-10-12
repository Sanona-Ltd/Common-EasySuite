<?php

namespace EasySuite\Common\Http\Middleware;

use Closure;
use EasySuite\Common\Jwt\VerifiedToken;
use EasySuite\Common\Support\Problem;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * `easysuite.scope:orbis:users.read` – verlangt ALLE aufgelisteten Scopes.
 * Muss nach `easysuite.token` laufen.
 */
class RequireScope
{
    public function handle(Request $request, Closure $next, string ...$scopes): Response
    {
        /** @var VerifiedToken|null $token */
        $token = $request->attributes->get(RequireToken::ATTRIBUTE);

        if (! $token) {
            return Problem::unauthorized('Missing bearer token.', null, 'invalid_request');
        }

        $missing = array_values(array_filter($scopes, fn (string $scope) => ! $token->hasScope($scope)));

        if ($missing !== []) {
            return Problem::response(403, 'Insufficient scope.', 'Missing: '.implode(' ', $missing));
        }

        return $next($request);
    }
}
