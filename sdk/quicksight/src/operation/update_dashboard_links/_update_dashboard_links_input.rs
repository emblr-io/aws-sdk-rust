// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDashboardLinksInput {
    /// <p>The ID of the Amazon Web Services account that contains the dashboard whose links you want to update.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID for the dashboard.</p>
    pub dashboard_id: ::std::option::Option<::std::string::String>,
    /// <p>list of analysis Amazon Resource Names (ARNs) to be linked to the dashboard.</p>
    pub link_entities: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl UpdateDashboardLinksInput {
    /// <p>The ID of the Amazon Web Services account that contains the dashboard whose links you want to update.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The ID for the dashboard.</p>
    pub fn dashboard_id(&self) -> ::std::option::Option<&str> {
        self.dashboard_id.as_deref()
    }
    /// <p>list of analysis Amazon Resource Names (ARNs) to be linked to the dashboard.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.link_entities.is_none()`.
    pub fn link_entities(&self) -> &[::std::string::String] {
        self.link_entities.as_deref().unwrap_or_default()
    }
}
impl UpdateDashboardLinksInput {
    /// Creates a new builder-style object to manufacture [`UpdateDashboardLinksInput`](crate::operation::update_dashboard_links::UpdateDashboardLinksInput).
    pub fn builder() -> crate::operation::update_dashboard_links::builders::UpdateDashboardLinksInputBuilder {
        crate::operation::update_dashboard_links::builders::UpdateDashboardLinksInputBuilder::default()
    }
}

/// A builder for [`UpdateDashboardLinksInput`](crate::operation::update_dashboard_links::UpdateDashboardLinksInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDashboardLinksInputBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) dashboard_id: ::std::option::Option<::std::string::String>,
    pub(crate) link_entities: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl UpdateDashboardLinksInputBuilder {
    /// <p>The ID of the Amazon Web Services account that contains the dashboard whose links you want to update.</p>
    /// This field is required.
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account that contains the dashboard whose links you want to update.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account that contains the dashboard whose links you want to update.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>The ID for the dashboard.</p>
    /// This field is required.
    pub fn dashboard_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dashboard_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for the dashboard.</p>
    pub fn set_dashboard_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dashboard_id = input;
        self
    }
    /// <p>The ID for the dashboard.</p>
    pub fn get_dashboard_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.dashboard_id
    }
    /// Appends an item to `link_entities`.
    ///
    /// To override the contents of this collection use [`set_link_entities`](Self::set_link_entities).
    ///
    /// <p>list of analysis Amazon Resource Names (ARNs) to be linked to the dashboard.</p>
    pub fn link_entities(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.link_entities.unwrap_or_default();
        v.push(input.into());
        self.link_entities = ::std::option::Option::Some(v);
        self
    }
    /// <p>list of analysis Amazon Resource Names (ARNs) to be linked to the dashboard.</p>
    pub fn set_link_entities(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.link_entities = input;
        self
    }
    /// <p>list of analysis Amazon Resource Names (ARNs) to be linked to the dashboard.</p>
    pub fn get_link_entities(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.link_entities
    }
    /// Consumes the builder and constructs a [`UpdateDashboardLinksInput`](crate::operation::update_dashboard_links::UpdateDashboardLinksInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_dashboard_links::UpdateDashboardLinksInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_dashboard_links::UpdateDashboardLinksInput {
            aws_account_id: self.aws_account_id,
            dashboard_id: self.dashboard_id,
            link_entities: self.link_entities,
        })
    }
}
