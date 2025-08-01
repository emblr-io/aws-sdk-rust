// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A request to update a <code>SqlInjectionMatchSet</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateSqlInjectionMatchSetInput {
    /// <p>The <code>SqlInjectionMatchSetId</code> of the <code>SqlInjectionMatchSet</code> that you want to update. <code>SqlInjectionMatchSetId</code> is returned by <code>CreateSqlInjectionMatchSet</code> and by <code>ListSqlInjectionMatchSets</code>.</p>
    pub sql_injection_match_set_id: ::std::option::Option<::std::string::String>,
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub change_token: ::std::option::Option<::std::string::String>,
    /// <p>An array of <code>SqlInjectionMatchSetUpdate</code> objects that you want to insert into or delete from a <code>SqlInjectionMatchSet</code>. For more information, see the applicable data types:</p>
    /// <ul>
    /// <li>
    /// <p><code>SqlInjectionMatchSetUpdate</code>: Contains <code>Action</code> and <code>SqlInjectionMatchTuple</code></p></li>
    /// <li>
    /// <p><code>SqlInjectionMatchTuple</code>: Contains <code>FieldToMatch</code> and <code>TextTransformation</code></p></li>
    /// <li>
    /// <p><code>FieldToMatch</code>: Contains <code>Data</code> and <code>Type</code></p></li>
    /// </ul>
    pub updates: ::std::option::Option<::std::vec::Vec<crate::types::SqlInjectionMatchSetUpdate>>,
}
impl UpdateSqlInjectionMatchSetInput {
    /// <p>The <code>SqlInjectionMatchSetId</code> of the <code>SqlInjectionMatchSet</code> that you want to update. <code>SqlInjectionMatchSetId</code> is returned by <code>CreateSqlInjectionMatchSet</code> and by <code>ListSqlInjectionMatchSets</code>.</p>
    pub fn sql_injection_match_set_id(&self) -> ::std::option::Option<&str> {
        self.sql_injection_match_set_id.as_deref()
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub fn change_token(&self) -> ::std::option::Option<&str> {
        self.change_token.as_deref()
    }
    /// <p>An array of <code>SqlInjectionMatchSetUpdate</code> objects that you want to insert into or delete from a <code>SqlInjectionMatchSet</code>. For more information, see the applicable data types:</p>
    /// <ul>
    /// <li>
    /// <p><code>SqlInjectionMatchSetUpdate</code>: Contains <code>Action</code> and <code>SqlInjectionMatchTuple</code></p></li>
    /// <li>
    /// <p><code>SqlInjectionMatchTuple</code>: Contains <code>FieldToMatch</code> and <code>TextTransformation</code></p></li>
    /// <li>
    /// <p><code>FieldToMatch</code>: Contains <code>Data</code> and <code>Type</code></p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.updates.is_none()`.
    pub fn updates(&self) -> &[crate::types::SqlInjectionMatchSetUpdate] {
        self.updates.as_deref().unwrap_or_default()
    }
}
impl UpdateSqlInjectionMatchSetInput {
    /// Creates a new builder-style object to manufacture [`UpdateSqlInjectionMatchSetInput`](crate::operation::update_sql_injection_match_set::UpdateSqlInjectionMatchSetInput).
    pub fn builder() -> crate::operation::update_sql_injection_match_set::builders::UpdateSqlInjectionMatchSetInputBuilder {
        crate::operation::update_sql_injection_match_set::builders::UpdateSqlInjectionMatchSetInputBuilder::default()
    }
}

/// A builder for [`UpdateSqlInjectionMatchSetInput`](crate::operation::update_sql_injection_match_set::UpdateSqlInjectionMatchSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateSqlInjectionMatchSetInputBuilder {
    pub(crate) sql_injection_match_set_id: ::std::option::Option<::std::string::String>,
    pub(crate) change_token: ::std::option::Option<::std::string::String>,
    pub(crate) updates: ::std::option::Option<::std::vec::Vec<crate::types::SqlInjectionMatchSetUpdate>>,
}
impl UpdateSqlInjectionMatchSetInputBuilder {
    /// <p>The <code>SqlInjectionMatchSetId</code> of the <code>SqlInjectionMatchSet</code> that you want to update. <code>SqlInjectionMatchSetId</code> is returned by <code>CreateSqlInjectionMatchSet</code> and by <code>ListSqlInjectionMatchSets</code>.</p>
    /// This field is required.
    pub fn sql_injection_match_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sql_injection_match_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>SqlInjectionMatchSetId</code> of the <code>SqlInjectionMatchSet</code> that you want to update. <code>SqlInjectionMatchSetId</code> is returned by <code>CreateSqlInjectionMatchSet</code> and by <code>ListSqlInjectionMatchSets</code>.</p>
    pub fn set_sql_injection_match_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sql_injection_match_set_id = input;
        self
    }
    /// <p>The <code>SqlInjectionMatchSetId</code> of the <code>SqlInjectionMatchSet</code> that you want to update. <code>SqlInjectionMatchSetId</code> is returned by <code>CreateSqlInjectionMatchSet</code> and by <code>ListSqlInjectionMatchSets</code>.</p>
    pub fn get_sql_injection_match_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.sql_injection_match_set_id
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    /// This field is required.
    pub fn change_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.change_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub fn set_change_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.change_token = input;
        self
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub fn get_change_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.change_token
    }
    /// Appends an item to `updates`.
    ///
    /// To override the contents of this collection use [`set_updates`](Self::set_updates).
    ///
    /// <p>An array of <code>SqlInjectionMatchSetUpdate</code> objects that you want to insert into or delete from a <code>SqlInjectionMatchSet</code>. For more information, see the applicable data types:</p>
    /// <ul>
    /// <li>
    /// <p><code>SqlInjectionMatchSetUpdate</code>: Contains <code>Action</code> and <code>SqlInjectionMatchTuple</code></p></li>
    /// <li>
    /// <p><code>SqlInjectionMatchTuple</code>: Contains <code>FieldToMatch</code> and <code>TextTransformation</code></p></li>
    /// <li>
    /// <p><code>FieldToMatch</code>: Contains <code>Data</code> and <code>Type</code></p></li>
    /// </ul>
    pub fn updates(mut self, input: crate::types::SqlInjectionMatchSetUpdate) -> Self {
        let mut v = self.updates.unwrap_or_default();
        v.push(input);
        self.updates = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of <code>SqlInjectionMatchSetUpdate</code> objects that you want to insert into or delete from a <code>SqlInjectionMatchSet</code>. For more information, see the applicable data types:</p>
    /// <ul>
    /// <li>
    /// <p><code>SqlInjectionMatchSetUpdate</code>: Contains <code>Action</code> and <code>SqlInjectionMatchTuple</code></p></li>
    /// <li>
    /// <p><code>SqlInjectionMatchTuple</code>: Contains <code>FieldToMatch</code> and <code>TextTransformation</code></p></li>
    /// <li>
    /// <p><code>FieldToMatch</code>: Contains <code>Data</code> and <code>Type</code></p></li>
    /// </ul>
    pub fn set_updates(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SqlInjectionMatchSetUpdate>>) -> Self {
        self.updates = input;
        self
    }
    /// <p>An array of <code>SqlInjectionMatchSetUpdate</code> objects that you want to insert into or delete from a <code>SqlInjectionMatchSet</code>. For more information, see the applicable data types:</p>
    /// <ul>
    /// <li>
    /// <p><code>SqlInjectionMatchSetUpdate</code>: Contains <code>Action</code> and <code>SqlInjectionMatchTuple</code></p></li>
    /// <li>
    /// <p><code>SqlInjectionMatchTuple</code>: Contains <code>FieldToMatch</code> and <code>TextTransformation</code></p></li>
    /// <li>
    /// <p><code>FieldToMatch</code>: Contains <code>Data</code> and <code>Type</code></p></li>
    /// </ul>
    pub fn get_updates(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SqlInjectionMatchSetUpdate>> {
        &self.updates
    }
    /// Consumes the builder and constructs a [`UpdateSqlInjectionMatchSetInput`](crate::operation::update_sql_injection_match_set::UpdateSqlInjectionMatchSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_sql_injection_match_set::UpdateSqlInjectionMatchSetInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_sql_injection_match_set::UpdateSqlInjectionMatchSetInput {
            sql_injection_match_set_id: self.sql_injection_match_set_id,
            change_token: self.change_token,
            updates: self.updates,
        })
    }
}
