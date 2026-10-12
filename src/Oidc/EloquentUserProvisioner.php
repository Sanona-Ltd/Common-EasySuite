<?php

namespace EasySuite\Common\Oidc;

use EasySuite\Common\Jwt\VerifiedToken;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

class EloquentUserProvisioner implements UserProvisioner
{
    public function resolve(array $profile, VerifiedToken $token): Authenticatable
    {
        /** @var class-string<Model&Authenticatable> $model */
        $model = config('easysuite.login.user_model');
        $uuidColumn = config('easysuite.login.uuid_column');
        $tenantColumn = config('easysuite.login.tenant_column');

        $attributes = array_filter([
            'name' => $profile['name'] ?? null,
            'email' => $profile['email'] ?? null,
        ], fn ($value) => $value !== null);

        if ($tenantColumn && $token->tid() !== null) {
            $attributes[$tenantColumn] = $token->tid();
        }

        return Model::unguarded(
            fn () => $model::query()->updateOrCreate([$uuidColumn => $profile['sub']], $attributes)
        );
    }
}
