<?php

namespace App\Http\Resources;

use Illuminate\Http\Resources\Json\JsonResource;

class Contact extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array
     */
    public function toArray($request)
    {
        return [
            'id'       => $this->id,
            'fullName' => $this->name,
            'tel'      => $this->phone,
            'created'  => (string)$this->created_at->format('Y-m-d'),
        ];
    }
}
