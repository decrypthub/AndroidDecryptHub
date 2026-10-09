import type http from 'node:http';

export type SendResponse = (code: number, body: unknown, contentType?: string) => void;

export type RouteContext = {
  req: http.IncomingMessage;
  res: http.ServerResponse;
  url: URL;
  send: SendResponse;
};

export type Route = {
  method?: string;
  path: string;
  prefix?: boolean;
  handler: () => unknown;
};
