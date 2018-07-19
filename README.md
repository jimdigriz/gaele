[Let's Encrypt](https://letsencrypt.org/) Client for [Google Cloud Load Balancer](https://cloud.google.com/load-balancing/).

[Google Cloud Platform](https://cloud.google.com/) does not support automatic provisioning and renewal of SSL certificates for their [Load Balancer](https://cloud.google.com/load-balancing/).  This project solves the problem by handling off the requests to your GCE instances for `/.well-known/acme-challenge` and proxying them to a Google App Engine service.

This makes for a simple, fire-and-forget and cost effective deployment compared to the other convoluted solutions worked out by others.

## Issues

 * consider moving some of the [environment variables](https://cloud.google.com/appengine/docs/flexible/python/runtime#environment_variables) into [project wide custom metadata](https://cloud.google.com/appengine/docs/flexible/python/runtime#metadata_server)
     * ie. adding a new domain should not require a deploy
 * only implemented is [RS256](https://tools.ietf.org/html/rfc7518#section-3.3)
     * [`urn:ietf:params:acme:error:badSignatureAlgorithm`](https://tools.ietf.org/html/draft-ietf-acme-acme-13#section-6.2) returns `algorithms`

## Related Links

 * [Let's Encrypt (LE)](https://letsencrypt.org/)
     * [`draft-ietf-acme-acme`](https://datatracker.ietf.org/doc/draft-ietf-acme-acme/)
     * [Boulder divergences from ACME](https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md)
 * [Google Cloud Platform (GCP)](https://cloud.google.com/)
     * [Google Cloud Load Balancer](https://cloud.google.com/load-balancing/)
     * [Google App Engine (GAE)](https://cloud.google.com/appengine/)
         * [Python on Google App Engine](https://cloud.google.com/appengine/docs/python/)
 * Alternatives (all involving either manual intervention or a dedicated GCE instance):
     * [Google Compute Engine Load balancer Let's Encrypt integration](http://blog.vuksan.com/2016/04/18/google-compute-load-balancer-lets-encrypt-integration)
     * [Google Cloud Global HTTP Load Balancer with Let's Encrypt](https://rogerhub.com/~r/sysadmin/2016/07/15/Google-Cloud-Global-HTTP-Load-Balancer-with-Lets-Encrypt/)
     * [Let's Encrypt Google Compute HTTP Load Balancer Docker Updater](https://github.com/bloomapi/letsencrypt-gcloud-balancer)
     * [Google Cloud HTTPs load balancing with Letsencrypt certificate](https://rubyinrails.com/2017/09/18/google-cloud-https-load-balancing-with-letsencrypt-certificate/)
     * [Secured WebSockets cluster on GCP with Let's Encrypt](https://github.com/elegantmonkeys/gcp-letsencrypt-websockets-cluster)

# Pre-flight

You will require the [Cloud SDK](https://cloud.google.com/appengine/docs/standard/python/download) to be installed and then you should clone the project with:

    git clone https://gitlab.com/coremem/gaele.git

You will also require `make` to be installed.

# Deploy

    make deploy PROJECT_ID=project-123456

## HTTP Server on GCE

Once you have deployed to GAE, you need to configure your HTTP servers to proxy requests to the service:

### nginx

    location /.well-known/acme-challenge/ {
        proxy_set_header [YOUR_PROJECT_ID].appspot.com/;
        proxy_pass http://[YOUR_PROJECT_ID].appspot.com/;
    }

# Development

For this need to set up the [Local Development Server](https://cloud.google.com/appengine/docs/standard/python/tools/using-local-server).  Once installed you should be able to just run from within the project:

    make
