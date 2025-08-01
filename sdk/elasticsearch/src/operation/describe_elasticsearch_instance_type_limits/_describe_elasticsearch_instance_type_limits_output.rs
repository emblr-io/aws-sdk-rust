// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for the parameters received from <code> <code>DescribeElasticsearchInstanceTypeLimits</code> </code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeElasticsearchInstanceTypeLimitsOutput {
    /// <p>Map of Role of the Instance and Limits that are applicable. Role performed by given Instance in Elasticsearch can be one of the following:</p>
    /// <ul>
    /// <li>data: If the given InstanceType is used as data node</li>
    /// <li>master: If the given InstanceType is used as master node</li>
    /// <li>ultra_warm: If the given InstanceType is used as warm node</li>
    /// </ul>
    /// <p></p>
    pub limits_by_role: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::Limits>>,
    _request_id: Option<String>,
}
impl DescribeElasticsearchInstanceTypeLimitsOutput {
    /// <p>Map of Role of the Instance and Limits that are applicable. Role performed by given Instance in Elasticsearch can be one of the following:</p>
    /// <ul>
    /// <li>data: If the given InstanceType is used as data node</li>
    /// <li>master: If the given InstanceType is used as master node</li>
    /// <li>ultra_warm: If the given InstanceType is used as warm node</li>
    /// </ul>
    /// <p></p>
    pub fn limits_by_role(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::Limits>> {
        self.limits_by_role.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeElasticsearchInstanceTypeLimitsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeElasticsearchInstanceTypeLimitsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeElasticsearchInstanceTypeLimitsOutput`](crate::operation::describe_elasticsearch_instance_type_limits::DescribeElasticsearchInstanceTypeLimitsOutput).
    pub fn builder() -> crate::operation::describe_elasticsearch_instance_type_limits::builders::DescribeElasticsearchInstanceTypeLimitsOutputBuilder
    {
        crate::operation::describe_elasticsearch_instance_type_limits::builders::DescribeElasticsearchInstanceTypeLimitsOutputBuilder::default()
    }
}

/// A builder for [`DescribeElasticsearchInstanceTypeLimitsOutput`](crate::operation::describe_elasticsearch_instance_type_limits::DescribeElasticsearchInstanceTypeLimitsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeElasticsearchInstanceTypeLimitsOutputBuilder {
    pub(crate) limits_by_role: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::Limits>>,
    _request_id: Option<String>,
}
impl DescribeElasticsearchInstanceTypeLimitsOutputBuilder {
    /// Adds a key-value pair to `limits_by_role`.
    ///
    /// To override the contents of this collection use [`set_limits_by_role`](Self::set_limits_by_role).
    ///
    /// <p>Map of Role of the Instance and Limits that are applicable. Role performed by given Instance in Elasticsearch can be one of the following:</p>
    /// <ul>
    /// <li>data: If the given InstanceType is used as data node</li>
    /// <li>master: If the given InstanceType is used as master node</li>
    /// <li>ultra_warm: If the given InstanceType is used as warm node</li>
    /// </ul>
    /// <p></p>
    pub fn limits_by_role(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::Limits) -> Self {
        let mut hash_map = self.limits_by_role.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.limits_by_role = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Map of Role of the Instance and Limits that are applicable. Role performed by given Instance in Elasticsearch can be one of the following:</p>
    /// <ul>
    /// <li>data: If the given InstanceType is used as data node</li>
    /// <li>master: If the given InstanceType is used as master node</li>
    /// <li>ultra_warm: If the given InstanceType is used as warm node</li>
    /// </ul>
    /// <p></p>
    pub fn set_limits_by_role(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::Limits>>,
    ) -> Self {
        self.limits_by_role = input;
        self
    }
    /// <p>Map of Role of the Instance and Limits that are applicable. Role performed by given Instance in Elasticsearch can be one of the following:</p>
    /// <ul>
    /// <li>data: If the given InstanceType is used as data node</li>
    /// <li>master: If the given InstanceType is used as master node</li>
    /// <li>ultra_warm: If the given InstanceType is used as warm node</li>
    /// </ul>
    /// <p></p>
    pub fn get_limits_by_role(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::Limits>> {
        &self.limits_by_role
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeElasticsearchInstanceTypeLimitsOutput`](crate::operation::describe_elasticsearch_instance_type_limits::DescribeElasticsearchInstanceTypeLimitsOutput).
    pub fn build(self) -> crate::operation::describe_elasticsearch_instance_type_limits::DescribeElasticsearchInstanceTypeLimitsOutput {
        crate::operation::describe_elasticsearch_instance_type_limits::DescribeElasticsearchInstanceTypeLimitsOutput {
            limits_by_role: self.limits_by_role,
            _request_id: self._request_id,
        }
    }
}
