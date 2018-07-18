[Let's Encrypt](https://letsencrypt.org/) Client for [Google Cloud Load Balancer](https://cloud.google.com/load-balancing/).

[Google Cloud Platform (GCP)](https://cloud.google.com/) does not support a mechanism to automatically provision SSL certificates for their [Load Balancer](https://cloud.google.com/load-balancing/) so this project enables you to proxy requests to `/.well-known/acme-challenge` from your GCE instances to a Google App Engine service and have everything automatically handled there.

This makes for a simple, fire-and-forget and cost effective deployment compared to the solutions worked out by others.

## Related Links

 * [Let's Encrypt](https://letsencrypt.org/)
     * [`draft-ietf-acme-acme`](https://datatracker.ietf.org/doc/draft-ietf-acme-acme/)
     * [Boulder divergences from ACME](https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md)
 * [Google Cloud Load Balancer](https://cloud.google.com/load-balancing/)
 * [Python on Google App Engine](https://cloud.google.com/appengine/docs/python/)
 * Alternatives (all involving either manual intervention or a dedicated GCE instance):
     * [Google Compute Engine Load balancer Let's Encrypt integration](http://blog.vuksan.com/2016/04/18/google-compute-load-balancer-lets-encrypt-integration)
     * [Google Cloud Global HTTP Load Balancer with Let's Encrypt](https://rogerhub.com/~r/sysadmin/2016/07/15/Google-Cloud-Global-HTTP-Load-Balancer-with-Lets-Encrypt/)
     * [Let's Encrypt Google Compute HTTP Load Balancer Docker Updater](https://github.com/bloomapi/letsencrypt-gcloud-balancer)
     * [Google Cloud HTTPs load balancing with Letsencrypt certificate](https://rubyinrails.com/2017/09/18/google-cloud-https-load-balancing-with-letsencrypt-certificate/)
     * [Secured WebSockets cluster on GCP with Let's Encrypt](https://github.com/elegantmonkeys/gcp-letsencrypt-websockets-cluster)

# Deploy

## HTTP Server on GCE

Once you have deployed to GAE, you need to configure your HTTP servers to proxy requests to the service:

### nginx

    location /.well-known/acme-challenge/ {
        proxy_set_header [YOUR_PROJECT_ID].appspot.com;
        proxy_pass http://[YOUR_PROJECT_ID].appspot.com;
    }
