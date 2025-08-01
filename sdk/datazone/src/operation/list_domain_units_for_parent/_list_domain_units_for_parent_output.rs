// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDomainUnitsForParentOutput {
    /// <p>The results returned by this action.</p>
    pub items: ::std::vec::Vec<crate::types::DomainUnitSummary>,
    /// <p>When the number of domain units is greater than the default value for the MaxResults parameter, or if you explicitly specify a value for MaxResults that is less than the number of domain units, the response includes a pagination token named NextToken. You can specify this NextToken value in a subsequent call to ListDomainUnitsForParent to list the next set of domain units.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDomainUnitsForParentOutput {
    /// <p>The results returned by this action.</p>
    pub fn items(&self) -> &[crate::types::DomainUnitSummary] {
        use std::ops::Deref;
        self.items.deref()
    }
    /// <p>When the number of domain units is greater than the default value for the MaxResults parameter, or if you explicitly specify a value for MaxResults that is less than the number of domain units, the response includes a pagination token named NextToken. You can specify this NextToken value in a subsequent call to ListDomainUnitsForParent to list the next set of domain units.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListDomainUnitsForParentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListDomainUnitsForParentOutput {
    /// Creates a new builder-style object to manufacture [`ListDomainUnitsForParentOutput`](crate::operation::list_domain_units_for_parent::ListDomainUnitsForParentOutput).
    pub fn builder() -> crate::operation::list_domain_units_for_parent::builders::ListDomainUnitsForParentOutputBuilder {
        crate::operation::list_domain_units_for_parent::builders::ListDomainUnitsForParentOutputBuilder::default()
    }
}

/// A builder for [`ListDomainUnitsForParentOutput`](crate::operation::list_domain_units_for_parent::ListDomainUnitsForParentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDomainUnitsForParentOutputBuilder {
    pub(crate) items: ::std::option::Option<::std::vec::Vec<crate::types::DomainUnitSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDomainUnitsForParentOutputBuilder {
    /// Appends an item to `items`.
    ///
    /// To override the contents of this collection use [`set_items`](Self::set_items).
    ///
    /// <p>The results returned by this action.</p>
    pub fn items(mut self, input: crate::types::DomainUnitSummary) -> Self {
        let mut v = self.items.unwrap_or_default();
        v.push(input);
        self.items = ::std::option::Option::Some(v);
        self
    }
    /// <p>The results returned by this action.</p>
    pub fn set_items(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DomainUnitSummary>>) -> Self {
        self.items = input;
        self
    }
    /// <p>The results returned by this action.</p>
    pub fn get_items(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DomainUnitSummary>> {
        &self.items
    }
    /// <p>When the number of domain units is greater than the default value for the MaxResults parameter, or if you explicitly specify a value for MaxResults that is less than the number of domain units, the response includes a pagination token named NextToken. You can specify this NextToken value in a subsequent call to ListDomainUnitsForParent to list the next set of domain units.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>When the number of domain units is greater than the default value for the MaxResults parameter, or if you explicitly specify a value for MaxResults that is less than the number of domain units, the response includes a pagination token named NextToken. You can specify this NextToken value in a subsequent call to ListDomainUnitsForParent to list the next set of domain units.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>When the number of domain units is greater than the default value for the MaxResults parameter, or if you explicitly specify a value for MaxResults that is less than the number of domain units, the response includes a pagination token named NextToken. You can specify this NextToken value in a subsequent call to ListDomainUnitsForParent to list the next set of domain units.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListDomainUnitsForParentOutput`](crate::operation::list_domain_units_for_parent::ListDomainUnitsForParentOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`items`](crate::operation::list_domain_units_for_parent::builders::ListDomainUnitsForParentOutputBuilder::items)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_domain_units_for_parent::ListDomainUnitsForParentOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_domain_units_for_parent::ListDomainUnitsForParentOutput {
            items: self.items.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "items",
                    "items was not specified but it is required when building ListDomainUnitsForParentOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
