// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This structure contains the information about the metric that is used for a period-based SLO.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ServiceLevelIndicatorMetric {
    /// <p>This is a string-to-string map that contains information about the type of object that this SLO is related to. It can include the following fields.</p>
    /// <ul>
    /// <li>
    /// <p><code>Type</code> designates the type of object that this SLO is related to.</p></li>
    /// <li>
    /// <p><code>ResourceType</code> specifies the type of the resource. This field is used only when the value of the <code>Type</code> field is <code>Resource</code> or <code>AWS::Resource</code>.</p></li>
    /// <li>
    /// <p><code>Name</code> specifies the name of the object. This is used only if the value of the <code>Type</code> field is <code>Service</code>, <code>RemoteService</code>, or <code>AWS::Service</code>.</p></li>
    /// <li>
    /// <p><code>Identifier</code> identifies the resource objects of this resource. This is used only if the value of the <code>Type</code> field is <code>Resource</code> or <code>AWS::Resource</code>.</p></li>
    /// <li>
    /// <p><code>Environment</code> specifies the location where this object is hosted, or what it belongs to.</p></li>
    /// </ul>
    pub key_attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>If the SLO monitors a specific operation of the service, this field displays that operation name.</p>
    pub operation_name: ::std::option::Option<::std::string::String>,
    /// <p>If the SLO monitors either the <code>LATENCY</code> or <code>AVAILABILITY</code> metric that Application Signals collects, this field displays which of those metrics is used.</p>
    pub metric_type: ::std::option::Option<crate::types::ServiceLevelIndicatorMetricType>,
    /// <p>If this SLO monitors a CloudWatch metric or the result of a CloudWatch metric math expression, this structure includes the information about that metric or expression.</p>
    pub metric_data_queries: ::std::vec::Vec<crate::types::MetricDataQuery>,
    /// <p>Identifies the dependency using the <code>DependencyKeyAttributes</code> and <code>DependencyOperationName</code>.</p>
    pub dependency_config: ::std::option::Option<crate::types::DependencyConfig>,
}
impl ServiceLevelIndicatorMetric {
    /// <p>This is a string-to-string map that contains information about the type of object that this SLO is related to. It can include the following fields.</p>
    /// <ul>
    /// <li>
    /// <p><code>Type</code> designates the type of object that this SLO is related to.</p></li>
    /// <li>
    /// <p><code>ResourceType</code> specifies the type of the resource. This field is used only when the value of the <code>Type</code> field is <code>Resource</code> or <code>AWS::Resource</code>.</p></li>
    /// <li>
    /// <p><code>Name</code> specifies the name of the object. This is used only if the value of the <code>Type</code> field is <code>Service</code>, <code>RemoteService</code>, or <code>AWS::Service</code>.</p></li>
    /// <li>
    /// <p><code>Identifier</code> identifies the resource objects of this resource. This is used only if the value of the <code>Type</code> field is <code>Resource</code> or <code>AWS::Resource</code>.</p></li>
    /// <li>
    /// <p><code>Environment</code> specifies the location where this object is hosted, or what it belongs to.</p></li>
    /// </ul>
    pub fn key_attributes(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.key_attributes.as_ref()
    }
    /// <p>If the SLO monitors a specific operation of the service, this field displays that operation name.</p>
    pub fn operation_name(&self) -> ::std::option::Option<&str> {
        self.operation_name.as_deref()
    }
    /// <p>If the SLO monitors either the <code>LATENCY</code> or <code>AVAILABILITY</code> metric that Application Signals collects, this field displays which of those metrics is used.</p>
    pub fn metric_type(&self) -> ::std::option::Option<&crate::types::ServiceLevelIndicatorMetricType> {
        self.metric_type.as_ref()
    }
    /// <p>If this SLO monitors a CloudWatch metric or the result of a CloudWatch metric math expression, this structure includes the information about that metric or expression.</p>
    pub fn metric_data_queries(&self) -> &[crate::types::MetricDataQuery] {
        use std::ops::Deref;
        self.metric_data_queries.deref()
    }
    /// <p>Identifies the dependency using the <code>DependencyKeyAttributes</code> and <code>DependencyOperationName</code>.</p>
    pub fn dependency_config(&self) -> ::std::option::Option<&crate::types::DependencyConfig> {
        self.dependency_config.as_ref()
    }
}
impl ServiceLevelIndicatorMetric {
    /// Creates a new builder-style object to manufacture [`ServiceLevelIndicatorMetric`](crate::types::ServiceLevelIndicatorMetric).
    pub fn builder() -> crate::types::builders::ServiceLevelIndicatorMetricBuilder {
        crate::types::builders::ServiceLevelIndicatorMetricBuilder::default()
    }
}

/// A builder for [`ServiceLevelIndicatorMetric`](crate::types::ServiceLevelIndicatorMetric).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ServiceLevelIndicatorMetricBuilder {
    pub(crate) key_attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) operation_name: ::std::option::Option<::std::string::String>,
    pub(crate) metric_type: ::std::option::Option<crate::types::ServiceLevelIndicatorMetricType>,
    pub(crate) metric_data_queries: ::std::option::Option<::std::vec::Vec<crate::types::MetricDataQuery>>,
    pub(crate) dependency_config: ::std::option::Option<crate::types::DependencyConfig>,
}
impl ServiceLevelIndicatorMetricBuilder {
    /// Adds a key-value pair to `key_attributes`.
    ///
    /// To override the contents of this collection use [`set_key_attributes`](Self::set_key_attributes).
    ///
    /// <p>This is a string-to-string map that contains information about the type of object that this SLO is related to. It can include the following fields.</p>
    /// <ul>
    /// <li>
    /// <p><code>Type</code> designates the type of object that this SLO is related to.</p></li>
    /// <li>
    /// <p><code>ResourceType</code> specifies the type of the resource. This field is used only when the value of the <code>Type</code> field is <code>Resource</code> or <code>AWS::Resource</code>.</p></li>
    /// <li>
    /// <p><code>Name</code> specifies the name of the object. This is used only if the value of the <code>Type</code> field is <code>Service</code>, <code>RemoteService</code>, or <code>AWS::Service</code>.</p></li>
    /// <li>
    /// <p><code>Identifier</code> identifies the resource objects of this resource. This is used only if the value of the <code>Type</code> field is <code>Resource</code> or <code>AWS::Resource</code>.</p></li>
    /// <li>
    /// <p><code>Environment</code> specifies the location where this object is hosted, or what it belongs to.</p></li>
    /// </ul>
    pub fn key_attributes(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.key_attributes.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.key_attributes = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>This is a string-to-string map that contains information about the type of object that this SLO is related to. It can include the following fields.</p>
    /// <ul>
    /// <li>
    /// <p><code>Type</code> designates the type of object that this SLO is related to.</p></li>
    /// <li>
    /// <p><code>ResourceType</code> specifies the type of the resource. This field is used only when the value of the <code>Type</code> field is <code>Resource</code> or <code>AWS::Resource</code>.</p></li>
    /// <li>
    /// <p><code>Name</code> specifies the name of the object. This is used only if the value of the <code>Type</code> field is <code>Service</code>, <code>RemoteService</code>, or <code>AWS::Service</code>.</p></li>
    /// <li>
    /// <p><code>Identifier</code> identifies the resource objects of this resource. This is used only if the value of the <code>Type</code> field is <code>Resource</code> or <code>AWS::Resource</code>.</p></li>
    /// <li>
    /// <p><code>Environment</code> specifies the location where this object is hosted, or what it belongs to.</p></li>
    /// </ul>
    pub fn set_key_attributes(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.key_attributes = input;
        self
    }
    /// <p>This is a string-to-string map that contains information about the type of object that this SLO is related to. It can include the following fields.</p>
    /// <ul>
    /// <li>
    /// <p><code>Type</code> designates the type of object that this SLO is related to.</p></li>
    /// <li>
    /// <p><code>ResourceType</code> specifies the type of the resource. This field is used only when the value of the <code>Type</code> field is <code>Resource</code> or <code>AWS::Resource</code>.</p></li>
    /// <li>
    /// <p><code>Name</code> specifies the name of the object. This is used only if the value of the <code>Type</code> field is <code>Service</code>, <code>RemoteService</code>, or <code>AWS::Service</code>.</p></li>
    /// <li>
    /// <p><code>Identifier</code> identifies the resource objects of this resource. This is used only if the value of the <code>Type</code> field is <code>Resource</code> or <code>AWS::Resource</code>.</p></li>
    /// <li>
    /// <p><code>Environment</code> specifies the location where this object is hosted, or what it belongs to.</p></li>
    /// </ul>
    pub fn get_key_attributes(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.key_attributes
    }
    /// <p>If the SLO monitors a specific operation of the service, this field displays that operation name.</p>
    pub fn operation_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operation_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the SLO monitors a specific operation of the service, this field displays that operation name.</p>
    pub fn set_operation_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operation_name = input;
        self
    }
    /// <p>If the SLO monitors a specific operation of the service, this field displays that operation name.</p>
    pub fn get_operation_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.operation_name
    }
    /// <p>If the SLO monitors either the <code>LATENCY</code> or <code>AVAILABILITY</code> metric that Application Signals collects, this field displays which of those metrics is used.</p>
    pub fn metric_type(mut self, input: crate::types::ServiceLevelIndicatorMetricType) -> Self {
        self.metric_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the SLO monitors either the <code>LATENCY</code> or <code>AVAILABILITY</code> metric that Application Signals collects, this field displays which of those metrics is used.</p>
    pub fn set_metric_type(mut self, input: ::std::option::Option<crate::types::ServiceLevelIndicatorMetricType>) -> Self {
        self.metric_type = input;
        self
    }
    /// <p>If the SLO monitors either the <code>LATENCY</code> or <code>AVAILABILITY</code> metric that Application Signals collects, this field displays which of those metrics is used.</p>
    pub fn get_metric_type(&self) -> &::std::option::Option<crate::types::ServiceLevelIndicatorMetricType> {
        &self.metric_type
    }
    /// Appends an item to `metric_data_queries`.
    ///
    /// To override the contents of this collection use [`set_metric_data_queries`](Self::set_metric_data_queries).
    ///
    /// <p>If this SLO monitors a CloudWatch metric or the result of a CloudWatch metric math expression, this structure includes the information about that metric or expression.</p>
    pub fn metric_data_queries(mut self, input: crate::types::MetricDataQuery) -> Self {
        let mut v = self.metric_data_queries.unwrap_or_default();
        v.push(input);
        self.metric_data_queries = ::std::option::Option::Some(v);
        self
    }
    /// <p>If this SLO monitors a CloudWatch metric or the result of a CloudWatch metric math expression, this structure includes the information about that metric or expression.</p>
    pub fn set_metric_data_queries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MetricDataQuery>>) -> Self {
        self.metric_data_queries = input;
        self
    }
    /// <p>If this SLO monitors a CloudWatch metric or the result of a CloudWatch metric math expression, this structure includes the information about that metric or expression.</p>
    pub fn get_metric_data_queries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MetricDataQuery>> {
        &self.metric_data_queries
    }
    /// <p>Identifies the dependency using the <code>DependencyKeyAttributes</code> and <code>DependencyOperationName</code>.</p>
    pub fn dependency_config(mut self, input: crate::types::DependencyConfig) -> Self {
        self.dependency_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Identifies the dependency using the <code>DependencyKeyAttributes</code> and <code>DependencyOperationName</code>.</p>
    pub fn set_dependency_config(mut self, input: ::std::option::Option<crate::types::DependencyConfig>) -> Self {
        self.dependency_config = input;
        self
    }
    /// <p>Identifies the dependency using the <code>DependencyKeyAttributes</code> and <code>DependencyOperationName</code>.</p>
    pub fn get_dependency_config(&self) -> &::std::option::Option<crate::types::DependencyConfig> {
        &self.dependency_config
    }
    /// Consumes the builder and constructs a [`ServiceLevelIndicatorMetric`](crate::types::ServiceLevelIndicatorMetric).
    /// This method will fail if any of the following fields are not set:
    /// - [`metric_data_queries`](crate::types::builders::ServiceLevelIndicatorMetricBuilder::metric_data_queries)
    pub fn build(self) -> ::std::result::Result<crate::types::ServiceLevelIndicatorMetric, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ServiceLevelIndicatorMetric {
            key_attributes: self.key_attributes,
            operation_name: self.operation_name,
            metric_type: self.metric_type,
            metric_data_queries: self.metric_data_queries.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "metric_data_queries",
                    "metric_data_queries was not specified but it is required when building ServiceLevelIndicatorMetric",
                )
            })?,
            dependency_config: self.dependency_config,
        })
    }
}
