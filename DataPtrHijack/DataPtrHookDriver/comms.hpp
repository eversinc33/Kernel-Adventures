#pragma once

#define CMD_LOG_MESSAGE 1

typedef struct _PAYLOAD {
    INT cmdType;
    INT status;
    INT executed;
} PAYLOAD;