[Let's Encrypt](https://letsencrypt.org/) Client for [Google Cloud Load Balancer](https://cloud.google.com/load-balancing/).

[Google Cloud Platform](https://cloud.google.com/) does not support automatic provisioning and renewal of SSL certificates for their [Load Balancer](https://cloud.google.com/load-balancing/).  This project solves the problem by handling off the [Let's Encrypt](https://letsencrypt.org/) requests to from your GCE instances by proxying them to a Google App Engine service.

This makes for a simple, fire-and-forget and cost effective solution when compared to other existing documented approaches described by the community.

`GAELE` (Google App Engine - Let's Encrypt) is a version two client.

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

**N.B.** it is recommended you use a dedicated project unless your existing project does not use or plan to use either GAE or Datastore

## Configuration

Configuration of the project is maintained through a [Google Datastore](https://cloud.google.com/appengine/docs/standard/python/datastore/) object with the key `gaele.configuration`.

The 'gaele.configuration' key in the Datastore contains the following:

 * **`directory` (default: staging):** URL pointing to the configuration directory:
     * **[staging](https://letsencrypt.org/docs/staging-environment/) [default]:** `https://acme-staging-v02.api.letsencrypt.org/directory`
     * **production:** `https://acme-v02.api.letsencrypt.org/directory`
 * **`domains` (default: `example.com`):** space seperated list of domains to run the service for
     * safe to edit throughout the lifecycle of the deployment without impact

After the deploy you should set `domains` to the list of domains you want to service and set `directory` to the production server URL.

### Advanced

Other properties are:

 * **`account`:** text of the URL to the account for this service
     * typically this is not edited but needs to be blanked when amending `directory` if already set
 * **`alg` (default: 'RS256' [[only supported](https://gitlab.com/coremem/gaele/issues/2)]):** algorithm to use
 * **`keysize` (default: 2048):** key length of public key to generate
 * **`period` (default: 0):** validatity time in seconds to request for the certificate for
     * **N.B.** Let's Encrypt does not support [`notBefore` or `notAfter`](https://tools.ietf.org/html/draft-ietf-acme-acme-13#section-7.1.3) so this should be left set to `0`

#### Informational

These must not be edited and should be treated read-only:

 * **`created`:** datetime when the configuration was created
 * **`modified`:** datetime when the configuration was last modified
 * **`key`:** blob of key

## HTTP Server on GCE

Once you have deployed to GAE, you need to configure your HTTP servers to proxy requests to the service:

### nginx

    location /.well-known/acme-challenge/ {
        proxy_set_header [YOUR_PROJECT_ID].appspot.com;
        proxy_pass http://[YOUR_PROJECT_ID].appspot.com;
    }

# Development

For this need to set up the [Local Development Server](https://cloud.google.com/appengine/docs/standard/python/tools/using-local-server).  Once installed you should be able to just run from within the project:

    make

You can open the [Admin Server UI by going to `http://localhost:8000`](http://localhost:8000) in your browser.

## Cron

To excercise the cron task can use the 'Run now' button in the [Cron Jobs](http://localhost:8000/cron) section of the [Admin Server UI](http://localhost:8000).
