<?php

namespace Spatie\Permission\Traits;

use Spatie\Permission\Contracts\Permission;

trait HasPermissions
{
    use RefreshesPermissionCache;
    
    /**
     * A user may have multiple direct permissions.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function permissions()
    {
        return $this->belongsToMany(
            config('laravel-permission.models.permission'),
            config('laravel-permission.table_names.user_has_permissions')
        );
    }
    
    /**
     * Grant the given permission(s) to a role.
     *
     * @param string|array|Permission|\Illuminate\Support\Collection $permissions
     *
     * @return HasPermissions
     */
    public function givePermissionTo(...$permissions)
    {
        $permissions = collect($permissions)
            ->flatten()
            ->map(function ($permission) {
                return $this->getStoredPermission($permission);
            })
            ->all();
        
        $this->permissions()->saveMany($permissions);
        
        $this->forgetCachedPermissions();
        
        return $this;
    }
    
    /**
     * Remove all current permissions and set the given ones.
     *
     * @param array ...$permissions
     *
     * @return $this
     */
    public function syncPermissions(...$permissions)
    {
        $this->permissions()->detach();
        
        return $this->givePermissionTo($permissions);
    }
    
    /**
     * Revoke the given permission.
     *
     * @param $permission
     *
     * @return HasPermissions
     */
    public function revokePermissionTo($permission)
    {
        $this->permissions()->detach($this->getStoredPermission($permission));
        
        $this->forgetCachedPermissions();
        
        return $this;
    }
    
    /**
     * @param string|array|Permission|\Illuminate\Support\Collection $permissions
     *
     * @return Permission
     */
    protected function getStoredPermission($permissions)
    {
        if (is_string($permissions)) {
            return app(Permission::class)->findByName($permissions);
        }
        
        if (is_array($permissions)) {
            return app(Permission::class)->whereIn('name', $permissions)->get();
        }
        
        return $permissions;
    }
    
    /**
     * Determine if the user has the given permission.
     *
     * @param string|Permission $permission
     *
     * @return bool
     */
    public function hasDirectPermission($permission)
    {
        if (is_array($permission)) {
            foreach ($permission as $perm) {
                $partial = $this->hasDirectPermission($perm);
                if (!$partial) {
                    return false;
                }
                return true;
            }
        } elseif (is_string($permission)) {
            $permission = app(Permission::class)->findByName($permission);
            
            if (!$permission) {
                return false;
            }
        }
        
        return $this->permissions->contains('id', $permission->id);
    }
    
    /**
     * Determine if the user may perform the given permission.
     *
     * @param string|Permission $permission
     *
     * @return bool
     */
    public function hasPermissionTo($permission)
    {
        return $this->hasDirectPermission($permission);
    }
    
    /**
     * @deprecated deprecated since version 1.0.1, use hasPermissionTo instead
     *
     * Determine if the user may perform the given permission.
     *
     * @param Permission $permission
     *
     * @return bool
     */
    public function hasPermission($permission)
    {
        return $this->hasDirectPermission($permission);
    }
    
    /**
     * Check if allowed to execute certain route by the name of the route (not the name of the permission)
     *
     * @param string $permissionRoute
     * @param bool $requireAll
     * @return bool
     */
    public function can($permissionRoute, $requireAll = false)
    {
        if (is_array($permissionRoute)) {
            foreach ($permissionRoute as $permName) {
                $hasPerm = $this->can($permName);
                if ($hasPerm && !$requireAll) {
                    return true;
                } elseif (!$hasPerm && $requireAll) {
                    return false;
                }
            }
            return $requireAll;
        } else {
            return $this->validatePermission($permissionRoute);
        }
    }
    
    protected function validatePermission($permission)
    {
        //No me fijo en la autorización de los roles, solamente en los permisos
        foreach ($this->permissions as $perm) {
            $all_allowed = explode(',', $perm->routes_allowed);
            $all_allowed = array_map('trim', $all_allowed); //clear white spaces at beggining and end
            foreach ($all_allowed  as $allowed) {
                if (substr($allowed, -1) == "*"){ //last char *
                    $routeName = substr($allowed, 0, -1);
                    if (mb_stripos($permission, $routeName) === 0) {
                        return true;
                    }
                }
                if ($allowed == $permission) {
                    return true;
                };
            }
        }
        return false;
    }
    
}
