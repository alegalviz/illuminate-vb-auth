<?php

return [
    'db' => [
        'connection'    => 'mysql',
        'prefix'        => 'vb_'
    ],
    'cookie' => [
        'hash'      => 'AdflkjEr90234asdlkj1349SDFkl',
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
