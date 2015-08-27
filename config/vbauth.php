<?php

return [
    'db' => [
        'connection'    => 'mysql',
        'table_prefix'  => ''
    ],
    'cookie' => [
        'hash'      => 'Va1WGqRMAtkRTuuzBOcPM43HDTWB',
        'prefix'    => 'bb_'
    ],
    'forum_path'    => 'http://example.com/',
    'user_groups' => [
        'Admin'             => [6],
        'Moderator'         => [7],
        'Super Moderator'   => [5],
        'User'              => [2],
        'Banned'            => [8],
        'Guest'             => [3],
    ],
    'user_columns' => [
        'userid',
        'username',
        'password',
        'usergroupid',
        'membergroupids',
        'email',
        'salt'
    ],
];
