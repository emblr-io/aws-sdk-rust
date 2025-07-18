// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AddFlowSourcesInput {
    /// <p>The Amazon Resource Name (ARN) of the flow that you want to update.</p>
    pub flow_arn: ::std::option::Option<::std::string::String>,
    /// <p>A list of sources that you want to add to the flow.</p>
    pub sources: ::std::option::Option<::std::vec::Vec<crate::types::SetSourceRequest>>,
}
impl AddFlowSourcesInput {
    /// <p>The Amazon Resource Name (ARN) of the flow that you want to update.</p>
    pub fn flow_arn(&self) -> ::std::option::Option<&str> {
        self.flow_arn.as_deref()
    }
    /// <p>A list of sources that you want to add to the flow.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sources.is_none()`.
    pub fn sources(&self) -> &[crate::types::SetSourceRequest] {
        self.sources.as_deref().unwrap_or_default()
    }
}
impl AddFlowSourcesInput {
    /// Creates a new builder-style object to manufacture [`AddFlowSourcesInput`](crate::operation::add_flow_sources::AddFlowSourcesInput).
    pub fn builder() -> crate::operation::add_flow_sources::builders::AddFlowSourcesInputBuilder {
        crate::operation::add_flow_sources::builders::AddFlowSourcesInputBuilder::default()
    }
}

/// A builder for [`AddFlowSourcesInput`](crate::operation::add_flow_sources::AddFlowSourcesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AddFlowSourcesInputBuilder {
    pub(crate) flow_arn: ::std::option::Option<::std::string::String>,
    pub(crate) sources: ::std::option::Option<::std::vec::Vec<crate::types::SetSourceRequest>>,
}
impl AddFlowSourcesInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the flow that you want to update.</p>
    /// This field is required.
    pub fn flow_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.flow_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the flow that you want to update.</p>
    pub fn set_flow_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.flow_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the flow that you want to update.</p>
    pub fn get_flow_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.flow_arn
    }
    /// Appends an item to `sources`.
    ///
    /// To override the contents of this collection use [`set_sources`](Self::set_sources).
    ///
    /// <p>A list of sources that you want to add to the flow.</p>
    pub fn sources(mut self, input: crate::types::SetSourceRequest) -> Self {
        let mut v = self.sources.unwrap_or_default();
        v.push(input);
        self.sources = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of sources that you want to add to the flow.</p>
    pub fn set_sources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SetSourceRequest>>) -> Self {
        self.sources = input;
        self
    }
    /// <p>A list of sources that you want to add to the flow.</p>
    pub fn get_sources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SetSourceRequest>> {
        &self.sources
    }
    /// Consumes the builder and constructs a [`AddFlowSourcesInput`](crate::operation::add_flow_sources::AddFlowSourcesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::add_flow_sources::AddFlowSourcesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::add_flow_sources::AddFlowSourcesInput {
            flow_arn: self.flow_arn,
            sources: self.sources,
        })
    }
}
