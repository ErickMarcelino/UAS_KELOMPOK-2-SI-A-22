<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use App\Support\Exceptions\OAuthException;
use App\Support\Traits\Authenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use App\Models\User;

class AuthController extends Controller
{
    use Authenticatable;

    /**
     * Get a JWT via given credentials.
     *
     * @return JsonResponse
     */

     public function register()
     {
         $validator = Validator::make(request()->all(),[
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'job' => 'required',
            'position' => 'required',
            'password' => 'required',
         ]);

         if ($validator->fails()) {
            return response()->json($validator->messages());
         }

         $user = User::create([
            'name' => request()->input('name'),
            'email' => request()->input('email'),
            'job' => request()->input('job'),
            'position' => request()->input('position'),
            'password' => bcrypt(request()->input('password')),
         ]);
         
     }

    public function login(LoginRequest $request): JsonResponse
    {
        if (!$token = Auth::attempt(credentials: $request->credentials())) {
            throw new OAuthException(code: 'invalid_credentials_provided');
        }

        return $this->responseWithToken(access_token: $token);
    }

    /**
     * Refresh a token.
     *
     * @return \App\Modules\Auth\Collections\TokenResource
     */
    public function refresh(): JsonResponse
    {
        return $this->responseWithToken(access_token: auth()->refresh());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout(): JsonResponse
    {
        auth()->logout();

        return new JsonResponse(['success' => true]);
    }
}
