// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides the category rules that are used to automatically categorize contacts based on uttered keywords and phrases.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Categories {
    /// <p>The category rules that have been matched in the analyzed segment.</p>
    pub matched_categories: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The category rule that was matched and when it occurred in the transcript.</p>
    pub matched_details: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::CategoryDetails>>,
}
impl Categories {
    /// <p>The category rules that have been matched in the analyzed segment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.matched_categories.is_none()`.
    pub fn matched_categories(&self) -> &[::std::string::String] {
        self.matched_categories.as_deref().unwrap_or_default()
    }
    /// <p>The category rule that was matched and when it occurred in the transcript.</p>
    pub fn matched_details(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::CategoryDetails>> {
        self.matched_details.as_ref()
    }
}
impl Categories {
    /// Creates a new builder-style object to manufacture [`Categories`](crate::types::Categories).
    pub fn builder() -> crate::types::builders::CategoriesBuilder {
        crate::types::builders::CategoriesBuilder::default()
    }
}

/// A builder for [`Categories`](crate::types::Categories).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CategoriesBuilder {
    pub(crate) matched_categories: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) matched_details: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::CategoryDetails>>,
}
impl CategoriesBuilder {
    /// Appends an item to `matched_categories`.
    ///
    /// To override the contents of this collection use [`set_matched_categories`](Self::set_matched_categories).
    ///
    /// <p>The category rules that have been matched in the analyzed segment.</p>
    pub fn matched_categories(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.matched_categories.unwrap_or_default();
        v.push(input.into());
        self.matched_categories = ::std::option::Option::Some(v);
        self
    }
    /// <p>The category rules that have been matched in the analyzed segment.</p>
    pub fn set_matched_categories(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.matched_categories = input;
        self
    }
    /// <p>The category rules that have been matched in the analyzed segment.</p>
    pub fn get_matched_categories(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.matched_categories
    }
    /// Adds a key-value pair to `matched_details`.
    ///
    /// To override the contents of this collection use [`set_matched_details`](Self::set_matched_details).
    ///
    /// <p>The category rule that was matched and when it occurred in the transcript.</p>
    pub fn matched_details(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::CategoryDetails) -> Self {
        let mut hash_map = self.matched_details.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.matched_details = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The category rule that was matched and when it occurred in the transcript.</p>
    pub fn set_matched_details(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::CategoryDetails>>,
    ) -> Self {
        self.matched_details = input;
        self
    }
    /// <p>The category rule that was matched and when it occurred in the transcript.</p>
    pub fn get_matched_details(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::CategoryDetails>> {
        &self.matched_details
    }
    /// Consumes the builder and constructs a [`Categories`](crate::types::Categories).
    pub fn build(self) -> crate::types::Categories {
        crate::types::Categories {
            matched_categories: self.matched_categories,
            matched_details: self.matched_details,
        }
    }
}
