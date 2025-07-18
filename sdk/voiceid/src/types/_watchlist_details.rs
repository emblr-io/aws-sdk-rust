// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details of the watchlists in a domain.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WatchlistDetails {
    /// <p>The identifier of the default watchlist.</p>
    pub default_watchlist_id: ::std::string::String,
}
impl WatchlistDetails {
    /// <p>The identifier of the default watchlist.</p>
    pub fn default_watchlist_id(&self) -> &str {
        use std::ops::Deref;
        self.default_watchlist_id.deref()
    }
}
impl WatchlistDetails {
    /// Creates a new builder-style object to manufacture [`WatchlistDetails`](crate::types::WatchlistDetails).
    pub fn builder() -> crate::types::builders::WatchlistDetailsBuilder {
        crate::types::builders::WatchlistDetailsBuilder::default()
    }
}

/// A builder for [`WatchlistDetails`](crate::types::WatchlistDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WatchlistDetailsBuilder {
    pub(crate) default_watchlist_id: ::std::option::Option<::std::string::String>,
}
impl WatchlistDetailsBuilder {
    /// <p>The identifier of the default watchlist.</p>
    /// This field is required.
    pub fn default_watchlist_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.default_watchlist_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the default watchlist.</p>
    pub fn set_default_watchlist_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.default_watchlist_id = input;
        self
    }
    /// <p>The identifier of the default watchlist.</p>
    pub fn get_default_watchlist_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.default_watchlist_id
    }
    /// Consumes the builder and constructs a [`WatchlistDetails`](crate::types::WatchlistDetails).
    /// This method will fail if any of the following fields are not set:
    /// - [`default_watchlist_id`](crate::types::builders::WatchlistDetailsBuilder::default_watchlist_id)
    pub fn build(self) -> ::std::result::Result<crate::types::WatchlistDetails, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::WatchlistDetails {
            default_watchlist_id: self.default_watchlist_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "default_watchlist_id",
                    "default_watchlist_id was not specified but it is required when building WatchlistDetails",
                )
            })?,
        })
    }
}
