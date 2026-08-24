FROM alpine:3.20

# Dummy Dockerfile for local/testing purposes
RUN echo "dummy docker image" > /tmp/dummy.txt

CMD ["sh", "-c", "cat /tmp/dummy.txt && sleep 3600"] 

COPY generate.sh /generate.sh

RUN chmod +x /generate.sh

CMD [ "/generate.sh" ]