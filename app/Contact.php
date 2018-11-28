<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Contact extends Model
{
    protected $fillable=[ 'name', 'phone' ];

    // Relationship with User model:
    public function user() {
        return $this->belongsTo(User::class);
    }
}
