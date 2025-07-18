// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration that specifies which cookies should be synchronized from the end user's local browser to the remote browser.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CookieSynchronizationConfiguration {
    /// <p>The list of cookie specifications that are allowed to be synchronized to the remote browser.</p>
    pub allowlist: ::std::vec::Vec<crate::types::CookieSpecification>,
    /// <p>The list of cookie specifications that are blocked from being synchronized to the remote browser.</p>
    pub blocklist: ::std::option::Option<::std::vec::Vec<crate::types::CookieSpecification>>,
}
impl CookieSynchronizationConfiguration {
    /// <p>The list of cookie specifications that are allowed to be synchronized to the remote browser.</p>
    pub fn allowlist(&self) -> &[crate::types::CookieSpecification] {
        use std::ops::Deref;
        self.allowlist.deref()
    }
    /// <p>The list of cookie specifications that are blocked from being synchronized to the remote browser.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.blocklist.is_none()`.
    pub fn blocklist(&self) -> &[crate::types::CookieSpecification] {
        self.blocklist.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for CookieSynchronizationConfiguration {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CookieSynchronizationConfiguration");
        formatter.field("allowlist", &"*** Sensitive Data Redacted ***");
        formatter.field("blocklist", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl CookieSynchronizationConfiguration {
    /// Creates a new builder-style object to manufacture [`CookieSynchronizationConfiguration`](crate::types::CookieSynchronizationConfiguration).
    pub fn builder() -> crate::types::builders::CookieSynchronizationConfigurationBuilder {
        crate::types::builders::CookieSynchronizationConfigurationBuilder::default()
    }
}

/// A builder for [`CookieSynchronizationConfiguration`](crate::types::CookieSynchronizationConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CookieSynchronizationConfigurationBuilder {
    pub(crate) allowlist: ::std::option::Option<::std::vec::Vec<crate::types::CookieSpecification>>,
    pub(crate) blocklist: ::std::option::Option<::std::vec::Vec<crate::types::CookieSpecification>>,
}
impl CookieSynchronizationConfigurationBuilder {
    /// Appends an item to `allowlist`.
    ///
    /// To override the contents of this collection use [`set_allowlist`](Self::set_allowlist).
    ///
    /// <p>The list of cookie specifications that are allowed to be synchronized to the remote browser.</p>
    pub fn allowlist(mut self, input: crate::types::CookieSpecification) -> Self {
        let mut v = self.allowlist.unwrap_or_default();
        v.push(input);
        self.allowlist = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of cookie specifications that are allowed to be synchronized to the remote browser.</p>
    pub fn set_allowlist(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CookieSpecification>>) -> Self {
        self.allowlist = input;
        self
    }
    /// <p>The list of cookie specifications that are allowed to be synchronized to the remote browser.</p>
    pub fn get_allowlist(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CookieSpecification>> {
        &self.allowlist
    }
    /// Appends an item to `blocklist`.
    ///
    /// To override the contents of this collection use [`set_blocklist`](Self::set_blocklist).
    ///
    /// <p>The list of cookie specifications that are blocked from being synchronized to the remote browser.</p>
    pub fn blocklist(mut self, input: crate::types::CookieSpecification) -> Self {
        let mut v = self.blocklist.unwrap_or_default();
        v.push(input);
        self.blocklist = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of cookie specifications that are blocked from being synchronized to the remote browser.</p>
    pub fn set_blocklist(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CookieSpecification>>) -> Self {
        self.blocklist = input;
        self
    }
    /// <p>The list of cookie specifications that are blocked from being synchronized to the remote browser.</p>
    pub fn get_blocklist(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CookieSpecification>> {
        &self.blocklist
    }
    /// Consumes the builder and constructs a [`CookieSynchronizationConfiguration`](crate::types::CookieSynchronizationConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`allowlist`](crate::types::builders::CookieSynchronizationConfigurationBuilder::allowlist)
    pub fn build(self) -> ::std::result::Result<crate::types::CookieSynchronizationConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CookieSynchronizationConfiguration {
            allowlist: self.allowlist.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "allowlist",
                    "allowlist was not specified but it is required when building CookieSynchronizationConfiguration",
                )
            })?,
            blocklist: self.blocklist,
        })
    }
}
impl ::std::fmt::Debug for CookieSynchronizationConfigurationBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CookieSynchronizationConfigurationBuilder");
        formatter.field("allowlist", &"*** Sensitive Data Redacted ***");
        formatter.field("blocklist", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
