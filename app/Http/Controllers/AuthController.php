<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use Laravel\Sanctum\PersonalAccessToken;

class AuthController extends Controller
{
    public function register(Request $request){
        $fields = $request->validate([
            'name' => 'required | string',
            'email' => 'required | string | unique:users,email',
            'password' => 'required | string | confirmed',
            
        ]);

        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => bcrypt($fields['password'])
        ]);

        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }

    public function login(Request $request){
        $fields = $request->validate([            
            'email' => 'required | string',
            'password' => 'required | string',
            
        ]);

        // Check email

        $user = User::where('email', $fields['email'])->first();

        // Check password

        if(!$user || !Hash::check($fields['password'], $user->password)){
            return response([
                'message' => 'Bad Credentials'
            ], 401);
        }

        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }
    
    public function logout(Request $request){

        /*
        * for Laravel 9
        * auth()->tokens()->delete();
        * provides an error then try using:
        * $accessToken = $request->bearerToken();
        * $token = PersonalAccessToken::findToken($accessToken);
        * $token->delete();
        */ 

        // auth()->user()->tokens()->delete(); DID NOT WORK!
        $accessToken = $request->bearerToken();
        $token = PersonalAccessToken::findToken($accessToken);
        $token->delete();

        return [
            'message' => 'Logged out'
        ];
    }
}
