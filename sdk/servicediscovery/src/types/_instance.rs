// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A complex type that contains information about an instance that Cloud Map creates when you submit a <code>RegisterInstance</code> request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Instance {
    /// <p>An identifier that you want to associate with the instance. Note the following:</p>
    /// <ul>
    /// <li>
    /// <p>If the service that's specified by <code>ServiceId</code> includes settings for an <code>SRV</code> record, the value of <code>InstanceId</code> is automatically included as part of the value for the <code>SRV</code> record. For more information, see <a href="https://docs.aws.amazon.com/cloud-map/latest/api/API_DnsRecord.html#cloudmap-Type-DnsRecord-Type">DnsRecord &gt; Type</a>.</p></li>
    /// <li>
    /// <p>You can use this value to update an existing instance.</p></li>
    /// <li>
    /// <p>To register a new instance, you must specify a value that's unique among instances that you register by using the same service.</p></li>
    /// <li>
    /// <p>If you specify an existing <code>InstanceId</code> and <code>ServiceId</code>, Cloud Map updates the existing DNS records. If there's also an existing health check, Cloud Map deletes the old health check and creates a new one.</p><note>
    /// <p>The health check isn't deleted immediately, so it will still appear for a while if you submit a <code>ListHealthChecks</code> request, for example.</p>
    /// </note></li>
    /// </ul>
    pub id: ::std::string::String,
    /// <p>A unique string that identifies the request and that allows failed <code>RegisterInstance</code> requests to be retried without the risk of executing the operation twice. You must use a unique <code>CreatorRequestId</code> string every time you submit a <code>RegisterInstance</code> request if you're registering additional instances for the same namespace and service. <code>CreatorRequestId</code> can be any unique string (for example, a date/time stamp).</p>
    pub creator_request_id: ::std::option::Option<::std::string::String>,
    /// <p>A string map that contains the following information for the service that you specify in <code>ServiceId</code>:</p>
    /// <ul>
    /// <li>
    /// <p>The attributes that apply to the records that are defined in the service.</p></li>
    /// <li>
    /// <p>For each attribute, the applicable value.</p></li>
    /// </ul><note>
    /// <p>Do not include sensitive information in the attributes if the namespace is discoverable by public DNS queries.</p>
    /// </note>
    /// <p>Supported attribute keys include the following:</p>
    /// <dl>
    /// <dt>
    /// AWS_ALIAS_DNS_NAME
    /// </dt>
    /// <dd>
    /// <p>If you want Cloud Map to create a Route&nbsp;53 alias record that routes traffic to an Elastic Load Balancing load balancer, specify the DNS name that's associated with the load balancer. For information about how to get the DNS name, see <a href="https://docs.aws.amazon.com/Route53/latest/APIReference/API_AliasTarget.html#Route53-Type-AliasTarget-DNSName">AliasTarget-&gt;DNSName</a> in the <i>Route&nbsp;53 API Reference</i>.</p>
    /// <p>Note the following:</p>
    /// <ul>
    /// <li>
    /// <p>The configuration for the service that's specified by <code>ServiceId</code> must include settings for an <code>A</code> record, an <code>AAAA</code> record, or both.</p></li>
    /// <li>
    /// <p>In the service that's specified by <code>ServiceId</code>, the value of <code>RoutingPolicy</code> must be <code>WEIGHTED</code>.</p></li>
    /// <li>
    /// <p>If the service that's specified by <code>ServiceId</code> includes <code>HealthCheckConfig</code> settings, Cloud Map creates the health check, but it won't associate the health check with the alias record.</p></li>
    /// <li>
    /// <p>Auto naming currently doesn't support creating alias records that route traffic to Amazon Web Services resources other than ELB load balancers.</p></li>
    /// <li>
    /// <p>If you specify a value for <code>AWS_ALIAS_DNS_NAME</code>, don't specify values for any of the <code>AWS_INSTANCE</code> attributes.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// AWS_EC2_INSTANCE_ID
    /// </dt>
    /// <dd>
    /// <p><i>HTTP namespaces only.</i> The Amazon EC2 instance ID for the instance. The <code>AWS_INSTANCE_IPV4</code> attribute contains the primary private IPv4 address.</p>
    /// </dd>
    /// <dt>
    /// AWS_INIT_HEALTH_STATUS
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes <code>HealthCheckCustomConfig</code>, you can optionally use <code>AWS_INIT_HEALTH_STATUS</code> to specify the initial status of the custom health check, <code>HEALTHY</code> or <code>UNHEALTHY</code>. If you don't specify a value for <code>AWS_INIT_HEALTH_STATUS</code>, the initial status is <code>HEALTHY</code>.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_CNAME
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes a <code>CNAME</code> record, the domain name that you want Route&nbsp;53 to return in response to DNS queries (for example, <code>example.com</code>).</p>
    /// <p>This value is required if the service specified by <code>ServiceId</code> includes settings for an <code>CNAME</code> record.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_IPV4
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes an <code>A</code> record, the IPv4 address that you want Route&nbsp;53 to return in response to DNS queries (for example, <code>192.0.2.44</code>).</p>
    /// <p>This value is required if the service specified by <code>ServiceId</code> includes settings for an <code>A</code> record. If the service includes settings for an <code>SRV</code> record, you must specify a value for <code>AWS_INSTANCE_IPV4</code>, <code>AWS_INSTANCE_IPV6</code>, or both.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_IPV6
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes an <code>AAAA</code> record, the IPv6 address that you want Route&nbsp;53 to return in response to DNS queries (for example, <code>2001:0db8:85a3:0000:0000:abcd:0001:2345</code>).</p>
    /// <p>This value is required if the service specified by <code>ServiceId</code> includes settings for an <code>AAAA</code> record. If the service includes settings for an <code>SRV</code> record, you must specify a value for <code>AWS_INSTANCE_IPV4</code>, <code>AWS_INSTANCE_IPV6</code>, or both.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_PORT
    /// </dt>
    /// <dd>
    /// <p>If the service includes an <code>SRV</code> record, the value that you want Route&nbsp;53 to return for the port.</p>
    /// <p>If the service includes <code>HealthCheckConfig</code>, the port on the endpoint that you want Route&nbsp;53 to send requests to.</p>
    /// <p>This value is required if you specified settings for an <code>SRV</code> record or a Route&nbsp;53 health check when you created the service.</p>
    /// </dd>
    /// </dl>
    pub attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl Instance {
    /// <p>An identifier that you want to associate with the instance. Note the following:</p>
    /// <ul>
    /// <li>
    /// <p>If the service that's specified by <code>ServiceId</code> includes settings for an <code>SRV</code> record, the value of <code>InstanceId</code> is automatically included as part of the value for the <code>SRV</code> record. For more information, see <a href="https://docs.aws.amazon.com/cloud-map/latest/api/API_DnsRecord.html#cloudmap-Type-DnsRecord-Type">DnsRecord &gt; Type</a>.</p></li>
    /// <li>
    /// <p>You can use this value to update an existing instance.</p></li>
    /// <li>
    /// <p>To register a new instance, you must specify a value that's unique among instances that you register by using the same service.</p></li>
    /// <li>
    /// <p>If you specify an existing <code>InstanceId</code> and <code>ServiceId</code>, Cloud Map updates the existing DNS records. If there's also an existing health check, Cloud Map deletes the old health check and creates a new one.</p><note>
    /// <p>The health check isn't deleted immediately, so it will still appear for a while if you submit a <code>ListHealthChecks</code> request, for example.</p>
    /// </note></li>
    /// </ul>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>A unique string that identifies the request and that allows failed <code>RegisterInstance</code> requests to be retried without the risk of executing the operation twice. You must use a unique <code>CreatorRequestId</code> string every time you submit a <code>RegisterInstance</code> request if you're registering additional instances for the same namespace and service. <code>CreatorRequestId</code> can be any unique string (for example, a date/time stamp).</p>
    pub fn creator_request_id(&self) -> ::std::option::Option<&str> {
        self.creator_request_id.as_deref()
    }
    /// <p>A string map that contains the following information for the service that you specify in <code>ServiceId</code>:</p>
    /// <ul>
    /// <li>
    /// <p>The attributes that apply to the records that are defined in the service.</p></li>
    /// <li>
    /// <p>For each attribute, the applicable value.</p></li>
    /// </ul><note>
    /// <p>Do not include sensitive information in the attributes if the namespace is discoverable by public DNS queries.</p>
    /// </note>
    /// <p>Supported attribute keys include the following:</p>
    /// <dl>
    /// <dt>
    /// AWS_ALIAS_DNS_NAME
    /// </dt>
    /// <dd>
    /// <p>If you want Cloud Map to create a Route&nbsp;53 alias record that routes traffic to an Elastic Load Balancing load balancer, specify the DNS name that's associated with the load balancer. For information about how to get the DNS name, see <a href="https://docs.aws.amazon.com/Route53/latest/APIReference/API_AliasTarget.html#Route53-Type-AliasTarget-DNSName">AliasTarget-&gt;DNSName</a> in the <i>Route&nbsp;53 API Reference</i>.</p>
    /// <p>Note the following:</p>
    /// <ul>
    /// <li>
    /// <p>The configuration for the service that's specified by <code>ServiceId</code> must include settings for an <code>A</code> record, an <code>AAAA</code> record, or both.</p></li>
    /// <li>
    /// <p>In the service that's specified by <code>ServiceId</code>, the value of <code>RoutingPolicy</code> must be <code>WEIGHTED</code>.</p></li>
    /// <li>
    /// <p>If the service that's specified by <code>ServiceId</code> includes <code>HealthCheckConfig</code> settings, Cloud Map creates the health check, but it won't associate the health check with the alias record.</p></li>
    /// <li>
    /// <p>Auto naming currently doesn't support creating alias records that route traffic to Amazon Web Services resources other than ELB load balancers.</p></li>
    /// <li>
    /// <p>If you specify a value for <code>AWS_ALIAS_DNS_NAME</code>, don't specify values for any of the <code>AWS_INSTANCE</code> attributes.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// AWS_EC2_INSTANCE_ID
    /// </dt>
    /// <dd>
    /// <p><i>HTTP namespaces only.</i> The Amazon EC2 instance ID for the instance. The <code>AWS_INSTANCE_IPV4</code> attribute contains the primary private IPv4 address.</p>
    /// </dd>
    /// <dt>
    /// AWS_INIT_HEALTH_STATUS
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes <code>HealthCheckCustomConfig</code>, you can optionally use <code>AWS_INIT_HEALTH_STATUS</code> to specify the initial status of the custom health check, <code>HEALTHY</code> or <code>UNHEALTHY</code>. If you don't specify a value for <code>AWS_INIT_HEALTH_STATUS</code>, the initial status is <code>HEALTHY</code>.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_CNAME
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes a <code>CNAME</code> record, the domain name that you want Route&nbsp;53 to return in response to DNS queries (for example, <code>example.com</code>).</p>
    /// <p>This value is required if the service specified by <code>ServiceId</code> includes settings for an <code>CNAME</code> record.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_IPV4
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes an <code>A</code> record, the IPv4 address that you want Route&nbsp;53 to return in response to DNS queries (for example, <code>192.0.2.44</code>).</p>
    /// <p>This value is required if the service specified by <code>ServiceId</code> includes settings for an <code>A</code> record. If the service includes settings for an <code>SRV</code> record, you must specify a value for <code>AWS_INSTANCE_IPV4</code>, <code>AWS_INSTANCE_IPV6</code>, or both.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_IPV6
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes an <code>AAAA</code> record, the IPv6 address that you want Route&nbsp;53 to return in response to DNS queries (for example, <code>2001:0db8:85a3:0000:0000:abcd:0001:2345</code>).</p>
    /// <p>This value is required if the service specified by <code>ServiceId</code> includes settings for an <code>AAAA</code> record. If the service includes settings for an <code>SRV</code> record, you must specify a value for <code>AWS_INSTANCE_IPV4</code>, <code>AWS_INSTANCE_IPV6</code>, or both.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_PORT
    /// </dt>
    /// <dd>
    /// <p>If the service includes an <code>SRV</code> record, the value that you want Route&nbsp;53 to return for the port.</p>
    /// <p>If the service includes <code>HealthCheckConfig</code>, the port on the endpoint that you want Route&nbsp;53 to send requests to.</p>
    /// <p>This value is required if you specified settings for an <code>SRV</code> record or a Route&nbsp;53 health check when you created the service.</p>
    /// </dd>
    /// </dl>
    pub fn attributes(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.attributes.as_ref()
    }
}
impl Instance {
    /// Creates a new builder-style object to manufacture [`Instance`](crate::types::Instance).
    pub fn builder() -> crate::types::builders::InstanceBuilder {
        crate::types::builders::InstanceBuilder::default()
    }
}

/// A builder for [`Instance`](crate::types::Instance).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InstanceBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) creator_request_id: ::std::option::Option<::std::string::String>,
    pub(crate) attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl InstanceBuilder {
    /// <p>An identifier that you want to associate with the instance. Note the following:</p>
    /// <ul>
    /// <li>
    /// <p>If the service that's specified by <code>ServiceId</code> includes settings for an <code>SRV</code> record, the value of <code>InstanceId</code> is automatically included as part of the value for the <code>SRV</code> record. For more information, see <a href="https://docs.aws.amazon.com/cloud-map/latest/api/API_DnsRecord.html#cloudmap-Type-DnsRecord-Type">DnsRecord &gt; Type</a>.</p></li>
    /// <li>
    /// <p>You can use this value to update an existing instance.</p></li>
    /// <li>
    /// <p>To register a new instance, you must specify a value that's unique among instances that you register by using the same service.</p></li>
    /// <li>
    /// <p>If you specify an existing <code>InstanceId</code> and <code>ServiceId</code>, Cloud Map updates the existing DNS records. If there's also an existing health check, Cloud Map deletes the old health check and creates a new one.</p><note>
    /// <p>The health check isn't deleted immediately, so it will still appear for a while if you submit a <code>ListHealthChecks</code> request, for example.</p>
    /// </note></li>
    /// </ul>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An identifier that you want to associate with the instance. Note the following:</p>
    /// <ul>
    /// <li>
    /// <p>If the service that's specified by <code>ServiceId</code> includes settings for an <code>SRV</code> record, the value of <code>InstanceId</code> is automatically included as part of the value for the <code>SRV</code> record. For more information, see <a href="https://docs.aws.amazon.com/cloud-map/latest/api/API_DnsRecord.html#cloudmap-Type-DnsRecord-Type">DnsRecord &gt; Type</a>.</p></li>
    /// <li>
    /// <p>You can use this value to update an existing instance.</p></li>
    /// <li>
    /// <p>To register a new instance, you must specify a value that's unique among instances that you register by using the same service.</p></li>
    /// <li>
    /// <p>If you specify an existing <code>InstanceId</code> and <code>ServiceId</code>, Cloud Map updates the existing DNS records. If there's also an existing health check, Cloud Map deletes the old health check and creates a new one.</p><note>
    /// <p>The health check isn't deleted immediately, so it will still appear for a while if you submit a <code>ListHealthChecks</code> request, for example.</p>
    /// </note></li>
    /// </ul>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>An identifier that you want to associate with the instance. Note the following:</p>
    /// <ul>
    /// <li>
    /// <p>If the service that's specified by <code>ServiceId</code> includes settings for an <code>SRV</code> record, the value of <code>InstanceId</code> is automatically included as part of the value for the <code>SRV</code> record. For more information, see <a href="https://docs.aws.amazon.com/cloud-map/latest/api/API_DnsRecord.html#cloudmap-Type-DnsRecord-Type">DnsRecord &gt; Type</a>.</p></li>
    /// <li>
    /// <p>You can use this value to update an existing instance.</p></li>
    /// <li>
    /// <p>To register a new instance, you must specify a value that's unique among instances that you register by using the same service.</p></li>
    /// <li>
    /// <p>If you specify an existing <code>InstanceId</code> and <code>ServiceId</code>, Cloud Map updates the existing DNS records. If there's also an existing health check, Cloud Map deletes the old health check and creates a new one.</p><note>
    /// <p>The health check isn't deleted immediately, so it will still appear for a while if you submit a <code>ListHealthChecks</code> request, for example.</p>
    /// </note></li>
    /// </ul>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>A unique string that identifies the request and that allows failed <code>RegisterInstance</code> requests to be retried without the risk of executing the operation twice. You must use a unique <code>CreatorRequestId</code> string every time you submit a <code>RegisterInstance</code> request if you're registering additional instances for the same namespace and service. <code>CreatorRequestId</code> can be any unique string (for example, a date/time stamp).</p>
    pub fn creator_request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.creator_request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique string that identifies the request and that allows failed <code>RegisterInstance</code> requests to be retried without the risk of executing the operation twice. You must use a unique <code>CreatorRequestId</code> string every time you submit a <code>RegisterInstance</code> request if you're registering additional instances for the same namespace and service. <code>CreatorRequestId</code> can be any unique string (for example, a date/time stamp).</p>
    pub fn set_creator_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.creator_request_id = input;
        self
    }
    /// <p>A unique string that identifies the request and that allows failed <code>RegisterInstance</code> requests to be retried without the risk of executing the operation twice. You must use a unique <code>CreatorRequestId</code> string every time you submit a <code>RegisterInstance</code> request if you're registering additional instances for the same namespace and service. <code>CreatorRequestId</code> can be any unique string (for example, a date/time stamp).</p>
    pub fn get_creator_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.creator_request_id
    }
    /// Adds a key-value pair to `attributes`.
    ///
    /// To override the contents of this collection use [`set_attributes`](Self::set_attributes).
    ///
    /// <p>A string map that contains the following information for the service that you specify in <code>ServiceId</code>:</p>
    /// <ul>
    /// <li>
    /// <p>The attributes that apply to the records that are defined in the service.</p></li>
    /// <li>
    /// <p>For each attribute, the applicable value.</p></li>
    /// </ul><note>
    /// <p>Do not include sensitive information in the attributes if the namespace is discoverable by public DNS queries.</p>
    /// </note>
    /// <p>Supported attribute keys include the following:</p>
    /// <dl>
    /// <dt>
    /// AWS_ALIAS_DNS_NAME
    /// </dt>
    /// <dd>
    /// <p>If you want Cloud Map to create a Route&nbsp;53 alias record that routes traffic to an Elastic Load Balancing load balancer, specify the DNS name that's associated with the load balancer. For information about how to get the DNS name, see <a href="https://docs.aws.amazon.com/Route53/latest/APIReference/API_AliasTarget.html#Route53-Type-AliasTarget-DNSName">AliasTarget-&gt;DNSName</a> in the <i>Route&nbsp;53 API Reference</i>.</p>
    /// <p>Note the following:</p>
    /// <ul>
    /// <li>
    /// <p>The configuration for the service that's specified by <code>ServiceId</code> must include settings for an <code>A</code> record, an <code>AAAA</code> record, or both.</p></li>
    /// <li>
    /// <p>In the service that's specified by <code>ServiceId</code>, the value of <code>RoutingPolicy</code> must be <code>WEIGHTED</code>.</p></li>
    /// <li>
    /// <p>If the service that's specified by <code>ServiceId</code> includes <code>HealthCheckConfig</code> settings, Cloud Map creates the health check, but it won't associate the health check with the alias record.</p></li>
    /// <li>
    /// <p>Auto naming currently doesn't support creating alias records that route traffic to Amazon Web Services resources other than ELB load balancers.</p></li>
    /// <li>
    /// <p>If you specify a value for <code>AWS_ALIAS_DNS_NAME</code>, don't specify values for any of the <code>AWS_INSTANCE</code> attributes.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// AWS_EC2_INSTANCE_ID
    /// </dt>
    /// <dd>
    /// <p><i>HTTP namespaces only.</i> The Amazon EC2 instance ID for the instance. The <code>AWS_INSTANCE_IPV4</code> attribute contains the primary private IPv4 address.</p>
    /// </dd>
    /// <dt>
    /// AWS_INIT_HEALTH_STATUS
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes <code>HealthCheckCustomConfig</code>, you can optionally use <code>AWS_INIT_HEALTH_STATUS</code> to specify the initial status of the custom health check, <code>HEALTHY</code> or <code>UNHEALTHY</code>. If you don't specify a value for <code>AWS_INIT_HEALTH_STATUS</code>, the initial status is <code>HEALTHY</code>.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_CNAME
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes a <code>CNAME</code> record, the domain name that you want Route&nbsp;53 to return in response to DNS queries (for example, <code>example.com</code>).</p>
    /// <p>This value is required if the service specified by <code>ServiceId</code> includes settings for an <code>CNAME</code> record.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_IPV4
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes an <code>A</code> record, the IPv4 address that you want Route&nbsp;53 to return in response to DNS queries (for example, <code>192.0.2.44</code>).</p>
    /// <p>This value is required if the service specified by <code>ServiceId</code> includes settings for an <code>A</code> record. If the service includes settings for an <code>SRV</code> record, you must specify a value for <code>AWS_INSTANCE_IPV4</code>, <code>AWS_INSTANCE_IPV6</code>, or both.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_IPV6
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes an <code>AAAA</code> record, the IPv6 address that you want Route&nbsp;53 to return in response to DNS queries (for example, <code>2001:0db8:85a3:0000:0000:abcd:0001:2345</code>).</p>
    /// <p>This value is required if the service specified by <code>ServiceId</code> includes settings for an <code>AAAA</code> record. If the service includes settings for an <code>SRV</code> record, you must specify a value for <code>AWS_INSTANCE_IPV4</code>, <code>AWS_INSTANCE_IPV6</code>, or both.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_PORT
    /// </dt>
    /// <dd>
    /// <p>If the service includes an <code>SRV</code> record, the value that you want Route&nbsp;53 to return for the port.</p>
    /// <p>If the service includes <code>HealthCheckConfig</code>, the port on the endpoint that you want Route&nbsp;53 to send requests to.</p>
    /// <p>This value is required if you specified settings for an <code>SRV</code> record or a Route&nbsp;53 health check when you created the service.</p>
    /// </dd>
    /// </dl>
    pub fn attributes(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.attributes.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.attributes = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A string map that contains the following information for the service that you specify in <code>ServiceId</code>:</p>
    /// <ul>
    /// <li>
    /// <p>The attributes that apply to the records that are defined in the service.</p></li>
    /// <li>
    /// <p>For each attribute, the applicable value.</p></li>
    /// </ul><note>
    /// <p>Do not include sensitive information in the attributes if the namespace is discoverable by public DNS queries.</p>
    /// </note>
    /// <p>Supported attribute keys include the following:</p>
    /// <dl>
    /// <dt>
    /// AWS_ALIAS_DNS_NAME
    /// </dt>
    /// <dd>
    /// <p>If you want Cloud Map to create a Route&nbsp;53 alias record that routes traffic to an Elastic Load Balancing load balancer, specify the DNS name that's associated with the load balancer. For information about how to get the DNS name, see <a href="https://docs.aws.amazon.com/Route53/latest/APIReference/API_AliasTarget.html#Route53-Type-AliasTarget-DNSName">AliasTarget-&gt;DNSName</a> in the <i>Route&nbsp;53 API Reference</i>.</p>
    /// <p>Note the following:</p>
    /// <ul>
    /// <li>
    /// <p>The configuration for the service that's specified by <code>ServiceId</code> must include settings for an <code>A</code> record, an <code>AAAA</code> record, or both.</p></li>
    /// <li>
    /// <p>In the service that's specified by <code>ServiceId</code>, the value of <code>RoutingPolicy</code> must be <code>WEIGHTED</code>.</p></li>
    /// <li>
    /// <p>If the service that's specified by <code>ServiceId</code> includes <code>HealthCheckConfig</code> settings, Cloud Map creates the health check, but it won't associate the health check with the alias record.</p></li>
    /// <li>
    /// <p>Auto naming currently doesn't support creating alias records that route traffic to Amazon Web Services resources other than ELB load balancers.</p></li>
    /// <li>
    /// <p>If you specify a value for <code>AWS_ALIAS_DNS_NAME</code>, don't specify values for any of the <code>AWS_INSTANCE</code> attributes.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// AWS_EC2_INSTANCE_ID
    /// </dt>
    /// <dd>
    /// <p><i>HTTP namespaces only.</i> The Amazon EC2 instance ID for the instance. The <code>AWS_INSTANCE_IPV4</code> attribute contains the primary private IPv4 address.</p>
    /// </dd>
    /// <dt>
    /// AWS_INIT_HEALTH_STATUS
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes <code>HealthCheckCustomConfig</code>, you can optionally use <code>AWS_INIT_HEALTH_STATUS</code> to specify the initial status of the custom health check, <code>HEALTHY</code> or <code>UNHEALTHY</code>. If you don't specify a value for <code>AWS_INIT_HEALTH_STATUS</code>, the initial status is <code>HEALTHY</code>.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_CNAME
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes a <code>CNAME</code> record, the domain name that you want Route&nbsp;53 to return in response to DNS queries (for example, <code>example.com</code>).</p>
    /// <p>This value is required if the service specified by <code>ServiceId</code> includes settings for an <code>CNAME</code> record.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_IPV4
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes an <code>A</code> record, the IPv4 address that you want Route&nbsp;53 to return in response to DNS queries (for example, <code>192.0.2.44</code>).</p>
    /// <p>This value is required if the service specified by <code>ServiceId</code> includes settings for an <code>A</code> record. If the service includes settings for an <code>SRV</code> record, you must specify a value for <code>AWS_INSTANCE_IPV4</code>, <code>AWS_INSTANCE_IPV6</code>, or both.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_IPV6
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes an <code>AAAA</code> record, the IPv6 address that you want Route&nbsp;53 to return in response to DNS queries (for example, <code>2001:0db8:85a3:0000:0000:abcd:0001:2345</code>).</p>
    /// <p>This value is required if the service specified by <code>ServiceId</code> includes settings for an <code>AAAA</code> record. If the service includes settings for an <code>SRV</code> record, you must specify a value for <code>AWS_INSTANCE_IPV4</code>, <code>AWS_INSTANCE_IPV6</code>, or both.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_PORT
    /// </dt>
    /// <dd>
    /// <p>If the service includes an <code>SRV</code> record, the value that you want Route&nbsp;53 to return for the port.</p>
    /// <p>If the service includes <code>HealthCheckConfig</code>, the port on the endpoint that you want Route&nbsp;53 to send requests to.</p>
    /// <p>This value is required if you specified settings for an <code>SRV</code> record or a Route&nbsp;53 health check when you created the service.</p>
    /// </dd>
    /// </dl>
    pub fn set_attributes(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.attributes = input;
        self
    }
    /// <p>A string map that contains the following information for the service that you specify in <code>ServiceId</code>:</p>
    /// <ul>
    /// <li>
    /// <p>The attributes that apply to the records that are defined in the service.</p></li>
    /// <li>
    /// <p>For each attribute, the applicable value.</p></li>
    /// </ul><note>
    /// <p>Do not include sensitive information in the attributes if the namespace is discoverable by public DNS queries.</p>
    /// </note>
    /// <p>Supported attribute keys include the following:</p>
    /// <dl>
    /// <dt>
    /// AWS_ALIAS_DNS_NAME
    /// </dt>
    /// <dd>
    /// <p>If you want Cloud Map to create a Route&nbsp;53 alias record that routes traffic to an Elastic Load Balancing load balancer, specify the DNS name that's associated with the load balancer. For information about how to get the DNS name, see <a href="https://docs.aws.amazon.com/Route53/latest/APIReference/API_AliasTarget.html#Route53-Type-AliasTarget-DNSName">AliasTarget-&gt;DNSName</a> in the <i>Route&nbsp;53 API Reference</i>.</p>
    /// <p>Note the following:</p>
    /// <ul>
    /// <li>
    /// <p>The configuration for the service that's specified by <code>ServiceId</code> must include settings for an <code>A</code> record, an <code>AAAA</code> record, or both.</p></li>
    /// <li>
    /// <p>In the service that's specified by <code>ServiceId</code>, the value of <code>RoutingPolicy</code> must be <code>WEIGHTED</code>.</p></li>
    /// <li>
    /// <p>If the service that's specified by <code>ServiceId</code> includes <code>HealthCheckConfig</code> settings, Cloud Map creates the health check, but it won't associate the health check with the alias record.</p></li>
    /// <li>
    /// <p>Auto naming currently doesn't support creating alias records that route traffic to Amazon Web Services resources other than ELB load balancers.</p></li>
    /// <li>
    /// <p>If you specify a value for <code>AWS_ALIAS_DNS_NAME</code>, don't specify values for any of the <code>AWS_INSTANCE</code> attributes.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// AWS_EC2_INSTANCE_ID
    /// </dt>
    /// <dd>
    /// <p><i>HTTP namespaces only.</i> The Amazon EC2 instance ID for the instance. The <code>AWS_INSTANCE_IPV4</code> attribute contains the primary private IPv4 address.</p>
    /// </dd>
    /// <dt>
    /// AWS_INIT_HEALTH_STATUS
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes <code>HealthCheckCustomConfig</code>, you can optionally use <code>AWS_INIT_HEALTH_STATUS</code> to specify the initial status of the custom health check, <code>HEALTHY</code> or <code>UNHEALTHY</code>. If you don't specify a value for <code>AWS_INIT_HEALTH_STATUS</code>, the initial status is <code>HEALTHY</code>.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_CNAME
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes a <code>CNAME</code> record, the domain name that you want Route&nbsp;53 to return in response to DNS queries (for example, <code>example.com</code>).</p>
    /// <p>This value is required if the service specified by <code>ServiceId</code> includes settings for an <code>CNAME</code> record.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_IPV4
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes an <code>A</code> record, the IPv4 address that you want Route&nbsp;53 to return in response to DNS queries (for example, <code>192.0.2.44</code>).</p>
    /// <p>This value is required if the service specified by <code>ServiceId</code> includes settings for an <code>A</code> record. If the service includes settings for an <code>SRV</code> record, you must specify a value for <code>AWS_INSTANCE_IPV4</code>, <code>AWS_INSTANCE_IPV6</code>, or both.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_IPV6
    /// </dt>
    /// <dd>
    /// <p>If the service configuration includes an <code>AAAA</code> record, the IPv6 address that you want Route&nbsp;53 to return in response to DNS queries (for example, <code>2001:0db8:85a3:0000:0000:abcd:0001:2345</code>).</p>
    /// <p>This value is required if the service specified by <code>ServiceId</code> includes settings for an <code>AAAA</code> record. If the service includes settings for an <code>SRV</code> record, you must specify a value for <code>AWS_INSTANCE_IPV4</code>, <code>AWS_INSTANCE_IPV6</code>, or both.</p>
    /// </dd>
    /// <dt>
    /// AWS_INSTANCE_PORT
    /// </dt>
    /// <dd>
    /// <p>If the service includes an <code>SRV</code> record, the value that you want Route&nbsp;53 to return for the port.</p>
    /// <p>If the service includes <code>HealthCheckConfig</code>, the port on the endpoint that you want Route&nbsp;53 to send requests to.</p>
    /// <p>This value is required if you specified settings for an <code>SRV</code> record or a Route&nbsp;53 health check when you created the service.</p>
    /// </dd>
    /// </dl>
    pub fn get_attributes(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.attributes
    }
    /// Consumes the builder and constructs a [`Instance`](crate::types::Instance).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::InstanceBuilder::id)
    pub fn build(self) -> ::std::result::Result<crate::types::Instance, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Instance {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building Instance",
                )
            })?,
            creator_request_id: self.creator_request_id,
            attributes: self.attributes,
        })
    }
}
