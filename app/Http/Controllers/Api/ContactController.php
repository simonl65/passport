<?php

namespace App\Http\Controllers\Api;

use App\Contact;
use App\Http\Controllers\Controller;
use App\Http\Resources\Contact as ContactResource;
use Illuminate\Http\Request;

class ContactController extends Controller
{
    /**
     * Protect with middleware:
     */
    public function __construct()
    {
        return $this->middleware('auth:api');
    }
    
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        // Only return contact(s) related to this user:
        $contacts = request()->user()->contacts;
        return ContactResource::collection($contacts);
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        // User is expected to be authenticated, so User model should be
        // available here:
        $contact = $request
                ->user()
                ->contacts()
                ->create( $request->all() );
        return new ContactResource($contact);
    }

    /**
     * Display the specified resource.
     *
     * @param  \App\Contact  $contact
     * @return \Illuminate\Http\Response
     */
    public function show(Contact $contact)
    {
        return new ContactResource($contact);
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \App\Contact  $contact
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, Contact $contact)
    {
        // Only allow updates on user's own resource:
        if( $request->user()->id !== $contact->user_id ) {
            return response()->json(['error' => 'Unauthorised action'], 401);
        }

        $contact->update( $request->all() );
        return new ContactResource($contact);
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  \App\Contact  $contact
     * @return \Illuminate\Http\Response
     */
    public function destroy(Contact $contact)
    {
        // Only allow updates on user's own resource:
        if( request()->user()->id !== $contact->user_id ) {
            return response()->json(['error' => 'Unauthorised action'], 401);
        }

        $contact = $contact->delete();

        return response()->json(null, 200);
    }
}
