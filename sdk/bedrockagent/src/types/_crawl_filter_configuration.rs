// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration of filtering the data source content. For example, configuring regular expression patterns to include or exclude certain content.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CrawlFilterConfiguration {
    /// <p>The type of filtering that you want to apply to certain objects or content of the data source. For example, the <code>PATTERN</code> type is regular expression patterns you can apply to filter your content.</p>
    pub r#type: crate::types::CrawlFilterConfigurationType,
    /// <p>The configuration of filtering certain objects or content types of the data source.</p>
    pub pattern_object_filter: ::std::option::Option<crate::types::PatternObjectFilterConfiguration>,
}
impl CrawlFilterConfiguration {
    /// <p>The type of filtering that you want to apply to certain objects or content of the data source. For example, the <code>PATTERN</code> type is regular expression patterns you can apply to filter your content.</p>
    pub fn r#type(&self) -> &crate::types::CrawlFilterConfigurationType {
        &self.r#type
    }
    /// <p>The configuration of filtering certain objects or content types of the data source.</p>
    pub fn pattern_object_filter(&self) -> ::std::option::Option<&crate::types::PatternObjectFilterConfiguration> {
        self.pattern_object_filter.as_ref()
    }
}
impl CrawlFilterConfiguration {
    /// Creates a new builder-style object to manufacture [`CrawlFilterConfiguration`](crate::types::CrawlFilterConfiguration).
    pub fn builder() -> crate::types::builders::CrawlFilterConfigurationBuilder {
        crate::types::builders::CrawlFilterConfigurationBuilder::default()
    }
}

/// A builder for [`CrawlFilterConfiguration`](crate::types::CrawlFilterConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CrawlFilterConfigurationBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::CrawlFilterConfigurationType>,
    pub(crate) pattern_object_filter: ::std::option::Option<crate::types::PatternObjectFilterConfiguration>,
}
impl CrawlFilterConfigurationBuilder {
    /// <p>The type of filtering that you want to apply to certain objects or content of the data source. For example, the <code>PATTERN</code> type is regular expression patterns you can apply to filter your content.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::CrawlFilterConfigurationType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of filtering that you want to apply to certain objects or content of the data source. For example, the <code>PATTERN</code> type is regular expression patterns you can apply to filter your content.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::CrawlFilterConfigurationType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of filtering that you want to apply to certain objects or content of the data source. For example, the <code>PATTERN</code> type is regular expression patterns you can apply to filter your content.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::CrawlFilterConfigurationType> {
        &self.r#type
    }
    /// <p>The configuration of filtering certain objects or content types of the data source.</p>
    pub fn pattern_object_filter(mut self, input: crate::types::PatternObjectFilterConfiguration) -> Self {
        self.pattern_object_filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration of filtering certain objects or content types of the data source.</p>
    pub fn set_pattern_object_filter(mut self, input: ::std::option::Option<crate::types::PatternObjectFilterConfiguration>) -> Self {
        self.pattern_object_filter = input;
        self
    }
    /// <p>The configuration of filtering certain objects or content types of the data source.</p>
    pub fn get_pattern_object_filter(&self) -> &::std::option::Option<crate::types::PatternObjectFilterConfiguration> {
        &self.pattern_object_filter
    }
    /// Consumes the builder and constructs a [`CrawlFilterConfiguration`](crate::types::CrawlFilterConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::CrawlFilterConfigurationBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::CrawlFilterConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CrawlFilterConfiguration {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building CrawlFilterConfiguration",
                )
            })?,
            pattern_object_filter: self.pattern_object_filter,
        })
    }
}
