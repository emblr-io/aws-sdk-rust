// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssignOpportunityOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for AssignOpportunityOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AssignOpportunityOutput {
    /// Creates a new builder-style object to manufacture [`AssignOpportunityOutput`](crate::operation::assign_opportunity::AssignOpportunityOutput).
    pub fn builder() -> crate::operation::assign_opportunity::builders::AssignOpportunityOutputBuilder {
        crate::operation::assign_opportunity::builders::AssignOpportunityOutputBuilder::default()
    }
}

/// A builder for [`AssignOpportunityOutput`](crate::operation::assign_opportunity::AssignOpportunityOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssignOpportunityOutputBuilder {
    _request_id: Option<String>,
}
impl AssignOpportunityOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AssignOpportunityOutput`](crate::operation::assign_opportunity::AssignOpportunityOutput).
    pub fn build(self) -> crate::operation::assign_opportunity::AssignOpportunityOutput {
        crate::operation::assign_opportunity::AssignOpportunityOutput {
            _request_id: self._request_id,
        }
    }
}
