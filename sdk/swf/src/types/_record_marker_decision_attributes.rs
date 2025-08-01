// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides the details of the <code>RecordMarker</code> decision.</p>
/// <p><b>Access Control</b></p>
/// <p>You can use IAM policies to control this decision's access to Amazon SWF resources as follows:</p>
/// <ul>
/// <li>
/// <p>Use a <code>Resource</code> element with the domain name to limit the action to only specified domains.</p></li>
/// <li>
/// <p>Use an <code>Action</code> element to allow or deny permission to call this action.</p></li>
/// <li>
/// <p>You cannot use an IAM policy to constrain this action's parameters.</p></li>
/// </ul>
/// <p>If the caller doesn't have sufficient permissions to invoke the action, or the parameter values fall outside the specified constraints, the action fails. The associated event attribute's <code>cause</code> parameter is set to <code>OPERATION_NOT_PERMITTED</code>. For details and example IAM policies, see <a href="https://docs.aws.amazon.com/amazonswf/latest/developerguide/swf-dev-iam.html">Using IAM to Manage Access to Amazon SWF Workflows</a> in the <i>Amazon SWF Developer Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RecordMarkerDecisionAttributes {
    /// <p>The name of the marker.</p>
    pub marker_name: ::std::string::String,
    /// <p>The details of the marker.</p>
    pub details: ::std::option::Option<::std::string::String>,
}
impl RecordMarkerDecisionAttributes {
    /// <p>The name of the marker.</p>
    pub fn marker_name(&self) -> &str {
        use std::ops::Deref;
        self.marker_name.deref()
    }
    /// <p>The details of the marker.</p>
    pub fn details(&self) -> ::std::option::Option<&str> {
        self.details.as_deref()
    }
}
impl RecordMarkerDecisionAttributes {
    /// Creates a new builder-style object to manufacture [`RecordMarkerDecisionAttributes`](crate::types::RecordMarkerDecisionAttributes).
    pub fn builder() -> crate::types::builders::RecordMarkerDecisionAttributesBuilder {
        crate::types::builders::RecordMarkerDecisionAttributesBuilder::default()
    }
}

/// A builder for [`RecordMarkerDecisionAttributes`](crate::types::RecordMarkerDecisionAttributes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RecordMarkerDecisionAttributesBuilder {
    pub(crate) marker_name: ::std::option::Option<::std::string::String>,
    pub(crate) details: ::std::option::Option<::std::string::String>,
}
impl RecordMarkerDecisionAttributesBuilder {
    /// <p>The name of the marker.</p>
    /// This field is required.
    pub fn marker_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the marker.</p>
    pub fn set_marker_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker_name = input;
        self
    }
    /// <p>The name of the marker.</p>
    pub fn get_marker_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker_name
    }
    /// <p>The details of the marker.</p>
    pub fn details(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.details = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The details of the marker.</p>
    pub fn set_details(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.details = input;
        self
    }
    /// <p>The details of the marker.</p>
    pub fn get_details(&self) -> &::std::option::Option<::std::string::String> {
        &self.details
    }
    /// Consumes the builder and constructs a [`RecordMarkerDecisionAttributes`](crate::types::RecordMarkerDecisionAttributes).
    /// This method will fail if any of the following fields are not set:
    /// - [`marker_name`](crate::types::builders::RecordMarkerDecisionAttributesBuilder::marker_name)
    pub fn build(self) -> ::std::result::Result<crate::types::RecordMarkerDecisionAttributes, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RecordMarkerDecisionAttributes {
            marker_name: self.marker_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "marker_name",
                    "marker_name was not specified but it is required when building RecordMarkerDecisionAttributes",
                )
            })?,
            details: self.details,
        })
    }
}
