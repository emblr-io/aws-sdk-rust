// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that contains the following elements:</p>
/// <ul>
/// <li>
/// <p>The <code>DashboardId</code> of the dashboard that has the visual that you want to embed.</p></li>
/// <li>
/// <p>The <code>SheetId</code> of the sheet that has the visual that you want to embed.</p></li>
/// <li>
/// <p>The <code>VisualId</code> of the visual that you want to embed.</p></li>
/// </ul>
/// <p>The <code>DashboardId</code>, <code>SheetId</code>, and <code>VisualId</code> can be found in the <code>IDs for developers</code> section of the <code>Embed visual</code> pane of the visual's on-visual menu of the Amazon QuickSight console. You can also get the <code>DashboardId</code> with a <code>ListDashboards</code> API operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DashboardVisualId {
    /// <p>The ID of the dashboard that has the visual that you want to embed. The <code>DashboardId</code> can be found in the <code>IDs for developers</code> section of the <code>Embed visual</code> pane of the visual's on-visual menu of the Amazon QuickSight console. You can also get the <code>DashboardId</code> with a <code>ListDashboards</code> API operation.</p>
    pub dashboard_id: ::std::string::String,
    /// <p>The ID of the sheet that the has visual that you want to embed. The <code>SheetId</code> can be found in the <code>IDs for developers</code> section of the <code>Embed visual</code> pane of the visual's on-visual menu of the Amazon QuickSight console.</p>
    pub sheet_id: ::std::string::String,
    /// <p>The ID of the visual that you want to embed. The <code>VisualID</code> can be found in the <code>IDs for developers</code> section of the <code>Embed visual</code> pane of the visual's on-visual menu of the Amazon QuickSight console.</p>
    pub visual_id: ::std::string::String,
}
impl DashboardVisualId {
    /// <p>The ID of the dashboard that has the visual that you want to embed. The <code>DashboardId</code> can be found in the <code>IDs for developers</code> section of the <code>Embed visual</code> pane of the visual's on-visual menu of the Amazon QuickSight console. You can also get the <code>DashboardId</code> with a <code>ListDashboards</code> API operation.</p>
    pub fn dashboard_id(&self) -> &str {
        use std::ops::Deref;
        self.dashboard_id.deref()
    }
    /// <p>The ID of the sheet that the has visual that you want to embed. The <code>SheetId</code> can be found in the <code>IDs for developers</code> section of the <code>Embed visual</code> pane of the visual's on-visual menu of the Amazon QuickSight console.</p>
    pub fn sheet_id(&self) -> &str {
        use std::ops::Deref;
        self.sheet_id.deref()
    }
    /// <p>The ID of the visual that you want to embed. The <code>VisualID</code> can be found in the <code>IDs for developers</code> section of the <code>Embed visual</code> pane of the visual's on-visual menu of the Amazon QuickSight console.</p>
    pub fn visual_id(&self) -> &str {
        use std::ops::Deref;
        self.visual_id.deref()
    }
}
impl DashboardVisualId {
    /// Creates a new builder-style object to manufacture [`DashboardVisualId`](crate::types::DashboardVisualId).
    pub fn builder() -> crate::types::builders::DashboardVisualIdBuilder {
        crate::types::builders::DashboardVisualIdBuilder::default()
    }
}

/// A builder for [`DashboardVisualId`](crate::types::DashboardVisualId).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DashboardVisualIdBuilder {
    pub(crate) dashboard_id: ::std::option::Option<::std::string::String>,
    pub(crate) sheet_id: ::std::option::Option<::std::string::String>,
    pub(crate) visual_id: ::std::option::Option<::std::string::String>,
}
impl DashboardVisualIdBuilder {
    /// <p>The ID of the dashboard that has the visual that you want to embed. The <code>DashboardId</code> can be found in the <code>IDs for developers</code> section of the <code>Embed visual</code> pane of the visual's on-visual menu of the Amazon QuickSight console. You can also get the <code>DashboardId</code> with a <code>ListDashboards</code> API operation.</p>
    /// This field is required.
    pub fn dashboard_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dashboard_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the dashboard that has the visual that you want to embed. The <code>DashboardId</code> can be found in the <code>IDs for developers</code> section of the <code>Embed visual</code> pane of the visual's on-visual menu of the Amazon QuickSight console. You can also get the <code>DashboardId</code> with a <code>ListDashboards</code> API operation.</p>
    pub fn set_dashboard_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dashboard_id = input;
        self
    }
    /// <p>The ID of the dashboard that has the visual that you want to embed. The <code>DashboardId</code> can be found in the <code>IDs for developers</code> section of the <code>Embed visual</code> pane of the visual's on-visual menu of the Amazon QuickSight console. You can also get the <code>DashboardId</code> with a <code>ListDashboards</code> API operation.</p>
    pub fn get_dashboard_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.dashboard_id
    }
    /// <p>The ID of the sheet that the has visual that you want to embed. The <code>SheetId</code> can be found in the <code>IDs for developers</code> section of the <code>Embed visual</code> pane of the visual's on-visual menu of the Amazon QuickSight console.</p>
    /// This field is required.
    pub fn sheet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sheet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the sheet that the has visual that you want to embed. The <code>SheetId</code> can be found in the <code>IDs for developers</code> section of the <code>Embed visual</code> pane of the visual's on-visual menu of the Amazon QuickSight console.</p>
    pub fn set_sheet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sheet_id = input;
        self
    }
    /// <p>The ID of the sheet that the has visual that you want to embed. The <code>SheetId</code> can be found in the <code>IDs for developers</code> section of the <code>Embed visual</code> pane of the visual's on-visual menu of the Amazon QuickSight console.</p>
    pub fn get_sheet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.sheet_id
    }
    /// <p>The ID of the visual that you want to embed. The <code>VisualID</code> can be found in the <code>IDs for developers</code> section of the <code>Embed visual</code> pane of the visual's on-visual menu of the Amazon QuickSight console.</p>
    /// This field is required.
    pub fn visual_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.visual_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the visual that you want to embed. The <code>VisualID</code> can be found in the <code>IDs for developers</code> section of the <code>Embed visual</code> pane of the visual's on-visual menu of the Amazon QuickSight console.</p>
    pub fn set_visual_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.visual_id = input;
        self
    }
    /// <p>The ID of the visual that you want to embed. The <code>VisualID</code> can be found in the <code>IDs for developers</code> section of the <code>Embed visual</code> pane of the visual's on-visual menu of the Amazon QuickSight console.</p>
    pub fn get_visual_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.visual_id
    }
    /// Consumes the builder and constructs a [`DashboardVisualId`](crate::types::DashboardVisualId).
    /// This method will fail if any of the following fields are not set:
    /// - [`dashboard_id`](crate::types::builders::DashboardVisualIdBuilder::dashboard_id)
    /// - [`sheet_id`](crate::types::builders::DashboardVisualIdBuilder::sheet_id)
    /// - [`visual_id`](crate::types::builders::DashboardVisualIdBuilder::visual_id)
    pub fn build(self) -> ::std::result::Result<crate::types::DashboardVisualId, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DashboardVisualId {
            dashboard_id: self.dashboard_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "dashboard_id",
                    "dashboard_id was not specified but it is required when building DashboardVisualId",
                )
            })?,
            sheet_id: self.sheet_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "sheet_id",
                    "sheet_id was not specified but it is required when building DashboardVisualId",
                )
            })?,
            visual_id: self.visual_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "visual_id",
                    "visual_id was not specified but it is required when building DashboardVisualId",
                )
            })?,
        })
    }
}
