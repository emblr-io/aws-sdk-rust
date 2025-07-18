// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetFindingDetailsInput {
    /// <p>A list of finding ARNs.</p>
    pub finding_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BatchGetFindingDetailsInput {
    /// <p>A list of finding ARNs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.finding_arns.is_none()`.
    pub fn finding_arns(&self) -> &[::std::string::String] {
        self.finding_arns.as_deref().unwrap_or_default()
    }
}
impl BatchGetFindingDetailsInput {
    /// Creates a new builder-style object to manufacture [`BatchGetFindingDetailsInput`](crate::operation::batch_get_finding_details::BatchGetFindingDetailsInput).
    pub fn builder() -> crate::operation::batch_get_finding_details::builders::BatchGetFindingDetailsInputBuilder {
        crate::operation::batch_get_finding_details::builders::BatchGetFindingDetailsInputBuilder::default()
    }
}

/// A builder for [`BatchGetFindingDetailsInput`](crate::operation::batch_get_finding_details::BatchGetFindingDetailsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetFindingDetailsInputBuilder {
    pub(crate) finding_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BatchGetFindingDetailsInputBuilder {
    /// Appends an item to `finding_arns`.
    ///
    /// To override the contents of this collection use [`set_finding_arns`](Self::set_finding_arns).
    ///
    /// <p>A list of finding ARNs.</p>
    pub fn finding_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.finding_arns.unwrap_or_default();
        v.push(input.into());
        self.finding_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of finding ARNs.</p>
    pub fn set_finding_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.finding_arns = input;
        self
    }
    /// <p>A list of finding ARNs.</p>
    pub fn get_finding_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.finding_arns
    }
    /// Consumes the builder and constructs a [`BatchGetFindingDetailsInput`](crate::operation::batch_get_finding_details::BatchGetFindingDetailsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::batch_get_finding_details::BatchGetFindingDetailsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::batch_get_finding_details::BatchGetFindingDetailsInput {
            finding_arns: self.finding_arns,
        })
    }
}
