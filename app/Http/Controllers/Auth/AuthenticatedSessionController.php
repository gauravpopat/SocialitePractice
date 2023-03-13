<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;
use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Models\User;
use App\Providers\RouteServiceProvider;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\View\View;
class AuthenticatedSessionController extends Controller
{
    /**
     * Display the login view.
     */
    public function create(): View
    {
        return view('auth.login');
    }

    /**
     * Handle an incoming authentication request.
     */
    public function store(LoginRequest $request): RedirectResponse
    {
        $request->authenticate();

        $request->session()->regenerate();

        return redirect()->intended(RouteServiceProvider::HOME);
    }

    /**
     * Destroy an authenticated session.
     */
    public function destroy(Request $request): RedirectResponse
    {
        Auth::guard('web')->logout();

        $request->session()->invalidate();

        $request->session()->regenerateToken();

        return redirect('/');
    }

    //send the user's request to github
    public function github()
    {
        return Socialite::driver('github')->redirect();
    }

    //get oauth request back from github to authenticate user
    public function githubRedirect()
    {
        $user = Socialite::driver('github')->user();
        
        $user = User::firstOrCreate([
            'email' => $user->email
        ], [
            'name'      => $user->name,
            'password'  => Hash::make(Str::random(24))
        ]);

        Auth::login($user,true);

        return redirect('/dashboard');
    }

    public function google()
    {
        return Socialite::driver('google')->redirect();
    }
    
    public function googleRedirect()
    {
        $user = Socialite::driver('google')->user();

        $user = User::firstOrCreate([
            'email' => $user->email
        ],
        [
            'name'      => $user->name,
            'password'  => Hash::make(Str::random(24))        
        ]);

        Auth::login($user,true);

        return redirect('/dashboard');
    }
}
