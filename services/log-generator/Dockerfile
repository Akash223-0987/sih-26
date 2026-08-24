FROM alpine:3.20

COPY generate.sh /generate.sh
RUN chmod +x /generate.sh
RUN sed -i 's/\r$//' /generate.sh

CMD ["sh", "-c", "tr -d '\\r' < /generate.sh > /tmp/gen.sh && chmod +x /tmp/gen.sh && /tmp/gen.sh"]