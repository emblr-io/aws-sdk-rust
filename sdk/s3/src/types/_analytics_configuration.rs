// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the configuration and any analyses for the analytics filter of an Amazon S3 bucket.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AnalyticsConfiguration {
    /// <p>The ID that identifies the analytics configuration.</p>
    pub id: ::std::string::String,
    /// <p>The filter used to describe a set of objects for analyses. A filter must have exactly one prefix, one tag, or one conjunction (AnalyticsAndOperator). If no filter is provided, all objects will be considered in any analysis.</p>
    pub filter: ::std::option::Option<crate::types::AnalyticsFilter>,
    /// <p>Contains data related to access patterns to be collected and made available to analyze the tradeoffs between different storage classes.</p>
    pub storage_class_analysis: ::std::option::Option<crate::types::StorageClassAnalysis>,
}
impl AnalyticsConfiguration {
    /// <p>The ID that identifies the analytics configuration.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The filter used to describe a set of objects for analyses. A filter must have exactly one prefix, one tag, or one conjunction (AnalyticsAndOperator). If no filter is provided, all objects will be considered in any analysis.</p>
    pub fn filter(&self) -> ::std::option::Option<&crate::types::AnalyticsFilter> {
        self.filter.as_ref()
    }
    /// <p>Contains data related to access patterns to be collected and made available to analyze the tradeoffs between different storage classes.</p>
    pub fn storage_class_analysis(&self) -> ::std::option::Option<&crate::types::StorageClassAnalysis> {
        self.storage_class_analysis.as_ref()
    }
}
impl AnalyticsConfiguration {
    /// Creates a new builder-style object to manufacture [`AnalyticsConfiguration`](crate::types::AnalyticsConfiguration).
    pub fn builder() -> crate::types::builders::AnalyticsConfigurationBuilder {
        crate::types::builders::AnalyticsConfigurationBuilder::default()
    }
}

/// A builder for [`AnalyticsConfiguration`](crate::types::AnalyticsConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AnalyticsConfigurationBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) filter: ::std::option::Option<crate::types::AnalyticsFilter>,
    pub(crate) storage_class_analysis: ::std::option::Option<crate::types::StorageClassAnalysis>,
}
impl AnalyticsConfigurationBuilder {
    /// <p>The ID that identifies the analytics configuration.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID that identifies the analytics configuration.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID that identifies the analytics configuration.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The filter used to describe a set of objects for analyses. A filter must have exactly one prefix, one tag, or one conjunction (AnalyticsAndOperator). If no filter is provided, all objects will be considered in any analysis.</p>
    pub fn filter(mut self, input: crate::types::AnalyticsFilter) -> Self {
        self.filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>The filter used to describe a set of objects for analyses. A filter must have exactly one prefix, one tag, or one conjunction (AnalyticsAndOperator). If no filter is provided, all objects will be considered in any analysis.</p>
    pub fn set_filter(mut self, input: ::std::option::Option<crate::types::AnalyticsFilter>) -> Self {
        self.filter = input;
        self
    }
    /// <p>The filter used to describe a set of objects for analyses. A filter must have exactly one prefix, one tag, or one conjunction (AnalyticsAndOperator). If no filter is provided, all objects will be considered in any analysis.</p>
    pub fn get_filter(&self) -> &::std::option::Option<crate::types::AnalyticsFilter> {
        &self.filter
    }
    /// <p>Contains data related to access patterns to be collected and made available to analyze the tradeoffs between different storage classes.</p>
    /// This field is required.
    pub fn storage_class_analysis(mut self, input: crate::types::StorageClassAnalysis) -> Self {
        self.storage_class_analysis = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains data related to access patterns to be collected and made available to analyze the tradeoffs between different storage classes.</p>
    pub fn set_storage_class_analysis(mut self, input: ::std::option::Option<crate::types::StorageClassAnalysis>) -> Self {
        self.storage_class_analysis = input;
        self
    }
    /// <p>Contains data related to access patterns to be collected and made available to analyze the tradeoffs between different storage classes.</p>
    pub fn get_storage_class_analysis(&self) -> &::std::option::Option<crate::types::StorageClassAnalysis> {
        &self.storage_class_analysis
    }
    /// Consumes the builder and constructs a [`AnalyticsConfiguration`](crate::types::AnalyticsConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::AnalyticsConfigurationBuilder::id)
    pub fn build(self) -> ::std::result::Result<crate::types::AnalyticsConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AnalyticsConfiguration {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building AnalyticsConfiguration",
                )
            })?,
            filter: self.filter,
            storage_class_analysis: self.storage_class_analysis,
        })
    }
}
