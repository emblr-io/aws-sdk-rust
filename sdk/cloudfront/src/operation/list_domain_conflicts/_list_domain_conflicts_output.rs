// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDomainConflictsOutput {
    /// <p>Contains details about the domain conflicts.</p>
    pub domain_conflicts: ::std::option::Option<::std::vec::Vec<crate::types::DomainConflict>>,
    /// <p>A token used for pagination of results returned in the response. You can use the token from the previous request to define where the current request should begin.</p>
    pub next_marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDomainConflictsOutput {
    /// <p>Contains details about the domain conflicts.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.domain_conflicts.is_none()`.
    pub fn domain_conflicts(&self) -> &[crate::types::DomainConflict] {
        self.domain_conflicts.as_deref().unwrap_or_default()
    }
    /// <p>A token used for pagination of results returned in the response. You can use the token from the previous request to define where the current request should begin.</p>
    pub fn next_marker(&self) -> ::std::option::Option<&str> {
        self.next_marker.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListDomainConflictsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListDomainConflictsOutput {
    /// Creates a new builder-style object to manufacture [`ListDomainConflictsOutput`](crate::operation::list_domain_conflicts::ListDomainConflictsOutput).
    pub fn builder() -> crate::operation::list_domain_conflicts::builders::ListDomainConflictsOutputBuilder {
        crate::operation::list_domain_conflicts::builders::ListDomainConflictsOutputBuilder::default()
    }
}

/// A builder for [`ListDomainConflictsOutput`](crate::operation::list_domain_conflicts::ListDomainConflictsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDomainConflictsOutputBuilder {
    pub(crate) domain_conflicts: ::std::option::Option<::std::vec::Vec<crate::types::DomainConflict>>,
    pub(crate) next_marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListDomainConflictsOutputBuilder {
    /// Appends an item to `domain_conflicts`.
    ///
    /// To override the contents of this collection use [`set_domain_conflicts`](Self::set_domain_conflicts).
    ///
    /// <p>Contains details about the domain conflicts.</p>
    pub fn domain_conflicts(mut self, input: crate::types::DomainConflict) -> Self {
        let mut v = self.domain_conflicts.unwrap_or_default();
        v.push(input);
        self.domain_conflicts = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains details about the domain conflicts.</p>
    pub fn set_domain_conflicts(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DomainConflict>>) -> Self {
        self.domain_conflicts = input;
        self
    }
    /// <p>Contains details about the domain conflicts.</p>
    pub fn get_domain_conflicts(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DomainConflict>> {
        &self.domain_conflicts
    }
    /// <p>A token used for pagination of results returned in the response. You can use the token from the previous request to define where the current request should begin.</p>
    pub fn next_marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token used for pagination of results returned in the response. You can use the token from the previous request to define where the current request should begin.</p>
    pub fn set_next_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_marker = input;
        self
    }
    /// <p>A token used for pagination of results returned in the response. You can use the token from the previous request to define where the current request should begin.</p>
    pub fn get_next_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_marker
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListDomainConflictsOutput`](crate::operation::list_domain_conflicts::ListDomainConflictsOutput).
    pub fn build(self) -> crate::operation::list_domain_conflicts::ListDomainConflictsOutput {
        crate::operation::list_domain_conflicts::ListDomainConflictsOutput {
            domain_conflicts: self.domain_conflicts,
            next_marker: self.next_marker,
            _request_id: self._request_id,
        }
    }
}
