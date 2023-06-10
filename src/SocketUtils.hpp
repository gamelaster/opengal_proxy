// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2023 Marek Kraus <gamelaster@outlook.com>

#pragma once

#ifdef WIN32
#define SCKT_RET_ERROR INVALID_SOCKET
#define SCKT_GET_ERROR WSAGetLastError()
#else
#define SCKT_RET_ERROR (-1)
#define SCKT_GET_ERROR (errno)

#endif