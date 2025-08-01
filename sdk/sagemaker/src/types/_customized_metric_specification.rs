// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A customized metric.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CustomizedMetricSpecification {
    /// <p>The name of the customized metric.</p>
    pub metric_name: ::std::option::Option<::std::string::String>,
    /// <p>The namespace of the customized metric.</p>
    pub namespace: ::std::option::Option<::std::string::String>,
    /// <p>The statistic of the customized metric.</p>
    pub statistic: ::std::option::Option<crate::types::Statistic>,
}
impl CustomizedMetricSpecification {
    /// <p>The name of the customized metric.</p>
    pub fn metric_name(&self) -> ::std::option::Option<&str> {
        self.metric_name.as_deref()
    }
    /// <p>The namespace of the customized metric.</p>
    pub fn namespace(&self) -> ::std::option::Option<&str> {
        self.namespace.as_deref()
    }
    /// <p>The statistic of the customized metric.</p>
    pub fn statistic(&self) -> ::std::option::Option<&crate::types::Statistic> {
        self.statistic.as_ref()
    }
}
impl CustomizedMetricSpecification {
    /// Creates a new builder-style object to manufacture [`CustomizedMetricSpecification`](crate::types::CustomizedMetricSpecification).
    pub fn builder() -> crate::types::builders::CustomizedMetricSpecificationBuilder {
        crate::types::builders::CustomizedMetricSpecificationBuilder::default()
    }
}

/// A builder for [`CustomizedMetricSpecification`](crate::types::CustomizedMetricSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CustomizedMetricSpecificationBuilder {
    pub(crate) metric_name: ::std::option::Option<::std::string::String>,
    pub(crate) namespace: ::std::option::Option<::std::string::String>,
    pub(crate) statistic: ::std::option::Option<crate::types::Statistic>,
}
impl CustomizedMetricSpecificationBuilder {
    /// <p>The name of the customized metric.</p>
    pub fn metric_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metric_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the customized metric.</p>
    pub fn set_metric_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metric_name = input;
        self
    }
    /// <p>The name of the customized metric.</p>
    pub fn get_metric_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.metric_name
    }
    /// <p>The namespace of the customized metric.</p>
    pub fn namespace(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The namespace of the customized metric.</p>
    pub fn set_namespace(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace = input;
        self
    }
    /// <p>The namespace of the customized metric.</p>
    pub fn get_namespace(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace
    }
    /// <p>The statistic of the customized metric.</p>
    pub fn statistic(mut self, input: crate::types::Statistic) -> Self {
        self.statistic = ::std::option::Option::Some(input);
        self
    }
    /// <p>The statistic of the customized metric.</p>
    pub fn set_statistic(mut self, input: ::std::option::Option<crate::types::Statistic>) -> Self {
        self.statistic = input;
        self
    }
    /// <p>The statistic of the customized metric.</p>
    pub fn get_statistic(&self) -> &::std::option::Option<crate::types::Statistic> {
        &self.statistic
    }
    /// Consumes the builder and constructs a [`CustomizedMetricSpecification`](crate::types::CustomizedMetricSpecification).
    pub fn build(self) -> crate::types::CustomizedMetricSpecification {
        crate::types::CustomizedMetricSpecification {
            metric_name: self.metric_name,
            namespace: self.namespace,
            statistic: self.statistic,
        }
    }
}
