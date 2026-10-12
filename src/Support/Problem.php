<?php

namespace EasySuite\Common\Support;

use Illuminate\Http\JsonResponse;

/** Fehlerantworten nach RFC 9457 (application/problem+json). */
final class Problem
{
    public static function response(int $status, string $title, ?string $detail = null, array $headers = []): JsonResponse
    {
        return response()->json(
            array_filter(['type' => 'about:blank', 'title' => $title, 'status' => $status, 'detail' => $detail]),
            $status,
            $headers + ['Content-Type' => 'application/problem+json']
        );
    }

    public static function unauthorized(string $title, ?string $detail = null, string $error = 'invalid_token'): JsonResponse
    {
        return self::response(401, $title, $detail, ['WWW-Authenticate' => 'Bearer error="'.$error.'"']);
    }
}
