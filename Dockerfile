FROM node:24.19.0-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS build

WORKDIR /build
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/core/package.json packages/core/package.json
COPY packages/policy/package.json packages/policy/package.json
COPY packages/transports/package.json packages/transports/package.json
COPY packages/cli/package.json packages/cli/package.json
RUN corepack enable && pnpm install --frozen-lockfile

COPY tsconfig.json tsconfig.base.json ./
COPY packages packages
RUN pnpm build
RUN pnpm --filter @mcp-restrictor/cli deploy --prod --no-optional /opt/mcp-restrictor && \
    find /opt/mcp-restrictor -type f -name '*.map' -delete && \
    find /opt/mcp-restrictor -type f -name '*.tsbuildinfo' -delete

FROM node:24.19.0-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03

RUN apt-get update && \
    apt-get install --no-install-recommends -y util-linux && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/mcp-restrictor /opt/mcp-restrictor
COPY --chmod=0555 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN test "$(id -u node)" = "1000" && \
    test "$(id -g node)" = "1000" && \
    install -d -o 1000 -g 1000 -m 0700 \
      /home/restrictor/.mcp-restrictor \
      /home/restrictor/.mcp-restrictor-key && \
    install -d -o 1000 -g 1000 -m 0755 /workspace && \
    chmod 0555 /opt/mcp-restrictor/dist/index.js && \
    ln -s /opt/mcp-restrictor/dist/index.js /usr/local/bin/mcp-restrictor

ENV HOME=/home/restrictor \
    NPM_CONFIG_CACHE=/tmp/npm-cache \
    MCP_RESTRICTOR_MASTER_KEY_FILE=/home/restrictor/.mcp-restrictor-key/oauth-master-key-v1
WORKDIR /workspace
USER 1000:1000
EXPOSE 17319
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["run","--bind","0.0.0.0"]
