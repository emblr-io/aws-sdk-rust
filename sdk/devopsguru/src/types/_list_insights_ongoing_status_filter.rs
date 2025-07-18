// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Used to filter for insights that have the status <code>ONGOING</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListInsightsOngoingStatusFilter {
    /// <p>Use to filter for either <code>REACTIVE</code> or <code>PROACTIVE</code> insights.</p>
    pub r#type: crate::types::InsightType,
}
impl ListInsightsOngoingStatusFilter {
    /// <p>Use to filter for either <code>REACTIVE</code> or <code>PROACTIVE</code> insights.</p>
    pub fn r#type(&self) -> &crate::types::InsightType {
        &self.r#type
    }
}
impl ListInsightsOngoingStatusFilter {
    /// Creates a new builder-style object to manufacture [`ListInsightsOngoingStatusFilter`](crate::types::ListInsightsOngoingStatusFilter).
    pub fn builder() -> crate::types::builders::ListInsightsOngoingStatusFilterBuilder {
        crate::types::builders::ListInsightsOngoingStatusFilterBuilder::default()
    }
}

/// A builder for [`ListInsightsOngoingStatusFilter`](crate::types::ListInsightsOngoingStatusFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListInsightsOngoingStatusFilterBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::InsightType>,
}
impl ListInsightsOngoingStatusFilterBuilder {
    /// <p>Use to filter for either <code>REACTIVE</code> or <code>PROACTIVE</code> insights.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::InsightType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Use to filter for either <code>REACTIVE</code> or <code>PROACTIVE</code> insights.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::InsightType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Use to filter for either <code>REACTIVE</code> or <code>PROACTIVE</code> insights.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::InsightType> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`ListInsightsOngoingStatusFilter`](crate::types::ListInsightsOngoingStatusFilter).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::ListInsightsOngoingStatusFilterBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::ListInsightsOngoingStatusFilter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ListInsightsOngoingStatusFilter {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building ListInsightsOngoingStatusFilter",
                )
            })?,
        })
    }
}
