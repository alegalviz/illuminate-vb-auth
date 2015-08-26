<?php

namespace Rixot\Illuminate\VBAuth\Facades;

use Illuminate\Support\Facades\Facade;

class VBAuth extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'vbauth';
    }
}
