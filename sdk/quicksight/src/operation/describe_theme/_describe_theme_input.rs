// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeThemeInput {
    /// <p>The ID of the Amazon Web Services account that contains the theme that you're describing.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID for the theme.</p>
    pub theme_id: ::std::option::Option<::std::string::String>,
    /// <p>The version number for the version to describe. If a <code>VersionNumber</code> parameter value isn't provided, the latest version of the theme is described.</p>
    pub version_number: ::std::option::Option<i64>,
    /// <p>The alias of the theme that you want to describe. If you name a specific alias, you describe the version that the alias points to. You can specify the latest version of the theme by providing the keyword <code>$LATEST</code> in the <code>AliasName</code> parameter. The keyword <code>$PUBLISHED</code> doesn't apply to themes.</p>
    pub alias_name: ::std::option::Option<::std::string::String>,
}
impl DescribeThemeInput {
    /// <p>The ID of the Amazon Web Services account that contains the theme that you're describing.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The ID for the theme.</p>
    pub fn theme_id(&self) -> ::std::option::Option<&str> {
        self.theme_id.as_deref()
    }
    /// <p>The version number for the version to describe. If a <code>VersionNumber</code> parameter value isn't provided, the latest version of the theme is described.</p>
    pub fn version_number(&self) -> ::std::option::Option<i64> {
        self.version_number
    }
    /// <p>The alias of the theme that you want to describe. If you name a specific alias, you describe the version that the alias points to. You can specify the latest version of the theme by providing the keyword <code>$LATEST</code> in the <code>AliasName</code> parameter. The keyword <code>$PUBLISHED</code> doesn't apply to themes.</p>
    pub fn alias_name(&self) -> ::std::option::Option<&str> {
        self.alias_name.as_deref()
    }
}
impl DescribeThemeInput {
    /// Creates a new builder-style object to manufacture [`DescribeThemeInput`](crate::operation::describe_theme::DescribeThemeInput).
    pub fn builder() -> crate::operation::describe_theme::builders::DescribeThemeInputBuilder {
        crate::operation::describe_theme::builders::DescribeThemeInputBuilder::default()
    }
}

/// A builder for [`DescribeThemeInput`](crate::operation::describe_theme::DescribeThemeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeThemeInputBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) theme_id: ::std::option::Option<::std::string::String>,
    pub(crate) version_number: ::std::option::Option<i64>,
    pub(crate) alias_name: ::std::option::Option<::std::string::String>,
}
impl DescribeThemeInputBuilder {
    /// <p>The ID of the Amazon Web Services account that contains the theme that you're describing.</p>
    /// This field is required.
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account that contains the theme that you're describing.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account that contains the theme that you're describing.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>The ID for the theme.</p>
    /// This field is required.
    pub fn theme_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.theme_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for the theme.</p>
    pub fn set_theme_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.theme_id = input;
        self
    }
    /// <p>The ID for the theme.</p>
    pub fn get_theme_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.theme_id
    }
    /// <p>The version number for the version to describe. If a <code>VersionNumber</code> parameter value isn't provided, the latest version of the theme is described.</p>
    pub fn version_number(mut self, input: i64) -> Self {
        self.version_number = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version number for the version to describe. If a <code>VersionNumber</code> parameter value isn't provided, the latest version of the theme is described.</p>
    pub fn set_version_number(mut self, input: ::std::option::Option<i64>) -> Self {
        self.version_number = input;
        self
    }
    /// <p>The version number for the version to describe. If a <code>VersionNumber</code> parameter value isn't provided, the latest version of the theme is described.</p>
    pub fn get_version_number(&self) -> &::std::option::Option<i64> {
        &self.version_number
    }
    /// <p>The alias of the theme that you want to describe. If you name a specific alias, you describe the version that the alias points to. You can specify the latest version of the theme by providing the keyword <code>$LATEST</code> in the <code>AliasName</code> parameter. The keyword <code>$PUBLISHED</code> doesn't apply to themes.</p>
    pub fn alias_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.alias_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The alias of the theme that you want to describe. If you name a specific alias, you describe the version that the alias points to. You can specify the latest version of the theme by providing the keyword <code>$LATEST</code> in the <code>AliasName</code> parameter. The keyword <code>$PUBLISHED</code> doesn't apply to themes.</p>
    pub fn set_alias_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.alias_name = input;
        self
    }
    /// <p>The alias of the theme that you want to describe. If you name a specific alias, you describe the version that the alias points to. You can specify the latest version of the theme by providing the keyword <code>$LATEST</code> in the <code>AliasName</code> parameter. The keyword <code>$PUBLISHED</code> doesn't apply to themes.</p>
    pub fn get_alias_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.alias_name
    }
    /// Consumes the builder and constructs a [`DescribeThemeInput`](crate::operation::describe_theme::DescribeThemeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_theme::DescribeThemeInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_theme::DescribeThemeInput {
            aws_account_id: self.aws_account_id,
            theme_id: self.theme_id,
            version_number: self.version_number,
            alias_name: self.alias_name,
        })
    }
}
