[Let's Encrypt](https://letsencrypt.org/) Client for [Google Cloud Load Balancer](https://cloud.google.com/load-balancing/).

[Google Cloud Platform](https://cloud.google.com/) does not support automatic provisioning and renewal of SSL certificates for their [Load Balancer](https://cloud.google.com/load-balancing/).  This project solves the problem by handling off the [Let's Encrypt](https://letsencrypt.org/) requests to from your GCE instances by proxying them to a Google App Engine service.

This makes for a simple, fire-and-forget and cost effective solution when compared to other existing documented approaches described by the community.

`gaele` (Google App Engine - Let's Encrypt) is a version two client.

**N.B.** this project is still non-functional and under development

## Related Links

 * [Let's Encrypt (LE)](https://letsencrypt.org/)
     * [`draft-ietf-acme-acme`](https://datatracker.ietf.org/doc/draft-ietf-acme-acme/)
     * [Boulder divergences from ACME](https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md)
 * [Google Cloud Platform (GCP)](https://cloud.google.com/)
     * [`gcloud alpha compute ssl-certificates create`](https://cloud.google.com/sdk/gcloud/reference/alpha/compute/ssl-certificates/create) - managed certificates
         * ['alpha'](https://cloud.google.com/sdk/docs/release-notes?hl=en#compute_engine_17)
         * [Issue Tracker #62049778](https://issuetracker.google.com/issues/62049778)
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

From the GCP perspective, you should have a deployment that has:

 * HTTPS (or SSL) load balancer, if you do not have a certificate use a self signed one (ignore the domain here, gaele will fix this later) and attach that to the load balancer:

         openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj /CN=example.invalid
         gcloud --project myproject-123456 compute ssl-certificates create mycert --certificate=cert.pem --private-key=key.pem
 * service account:

         gcloud --project myproject-123456 iam roles create gaele --permissions compute.sslCertificates.create,compute.sslCertificates.delete,compute.sslCertificates.get,compute.targetHttpsProxies.get,compute.targetHttpsProxies.setSslCertificates,compute.targetSslProxies.get,compute.targetSslProxies.setSslCertificates --stage GA
         gcloud projects add-iam-policy-binding myproject-123456 --member serviceAccount:gaele-123456@appspot.gserviceaccount.com --role=projects/myproject-123456/roles/gaele

# Deploy

    make deploy PROJECT_ID=gaele-123456

**N.B.** it is recommended you use a dedicated project unless your existing project space does not use or plan to use either GAE or the Datastore

Remember to active the `compute` API on the project you deploy to:

    gcloud --project gaele-123456 services enable compute.googleapis.com

## Configuration

Configuration of the project is maintained through a [Google Datastore](https://cloud.google.com/appengine/docs/standard/python/datastore/) object with the key `gaele.configuration`.

The 'gaele.configuration' key in the Datastore contains the following:

 * **`directory` (default: staging):** URL pointing to the configuration directory:
     * **[staging](https://letsencrypt.org/docs/staging-environment/) [default]:** `https://acme-staging-v02.api.letsencrypt.org/directory`
     * **production:** `https://acme-v02.api.letsencrypt.org/directory`
 * **`domains` (default: empty):** newline seperated list of domains to run the service for
     * safe to edit throughout the lifecycle of the deployment without impact
 * **`project` (default: project deployed to):** project that contains the load balancer
 * **`loadbalancer` (default: empty):** newline seperated list `[type]:[name]` of load balancers to configure
     * `https:mylb`: would configure a [Target (HTTPS) Proxy](https://cloud.google.com/load-balancing/docs/target-proxies)
     * `ssl:mylb`: would configure a [Target SSL Proxy](https://cloud.google.com/load-balancing/docs/ssl/setting-up-ssl)
 * **`token` (default: [UUIDv4](https://en.wikipedia.org/wiki/Universally_unique_identifier#Version_4_(random))):** used via `x-gaele-token` to bypass [cron security check](https://cloud.google.com/appengine/docs/flexible/python/scheduling-jobs-with-cron-yaml#validating_cron_requests); typically you never need to change this

After the deploy you should set `domains` to the list of domains you want to service and set `directory` to the production server URL.

### Advanced

These should be left un-touched, as they are used internally:

 * **`key`:** PEM of the private key

## HTTP Server on GCE

Once you have deployed to GAE, you need to configure your HTTP servers to proxy requests to the service]:

### nginx

    location /.well-known/acme-challenge/ {
        proxy_set_header host [YOUR_PROJECT_ID].appspot.com;
        proxy_pass http://[YOUR_PROJECT_ID].appspot.com;
    }

# Development

For this need to set up the [Local Development Server](https://cloud.google.com/appengine/docs/standard/python/tools/using-local-server).  Once installed you should be able to just run from within the project:

    make

You can open the [Admin Server UI by going to `http://localhost:8000`](http://localhost:8000) in your browser.

## Cron

To excercise the cron task can use the 'Run now' button in the [Cron Jobs](http://localhost:8000/cron) section of the [Admin Server UI](http://localhost:8000).
