// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteProvisionedProductPlanInput {
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub accept_language: ::std::option::Option<::std::string::String>,
    /// <p>The plan identifier.</p>
    pub plan_id: ::std::option::Option<::std::string::String>,
    /// <p>If set to true, Service Catalog stops managing the specified provisioned product even if it cannot delete the underlying resources.</p>
    pub ignore_errors: ::std::option::Option<bool>,
}
impl DeleteProvisionedProductPlanInput {
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn accept_language(&self) -> ::std::option::Option<&str> {
        self.accept_language.as_deref()
    }
    /// <p>The plan identifier.</p>
    pub fn plan_id(&self) -> ::std::option::Option<&str> {
        self.plan_id.as_deref()
    }
    /// <p>If set to true, Service Catalog stops managing the specified provisioned product even if it cannot delete the underlying resources.</p>
    pub fn ignore_errors(&self) -> ::std::option::Option<bool> {
        self.ignore_errors
    }
}
impl DeleteProvisionedProductPlanInput {
    /// Creates a new builder-style object to manufacture [`DeleteProvisionedProductPlanInput`](crate::operation::delete_provisioned_product_plan::DeleteProvisionedProductPlanInput).
    pub fn builder() -> crate::operation::delete_provisioned_product_plan::builders::DeleteProvisionedProductPlanInputBuilder {
        crate::operation::delete_provisioned_product_plan::builders::DeleteProvisionedProductPlanInputBuilder::default()
    }
}

/// A builder for [`DeleteProvisionedProductPlanInput`](crate::operation::delete_provisioned_product_plan::DeleteProvisionedProductPlanInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteProvisionedProductPlanInputBuilder {
    pub(crate) accept_language: ::std::option::Option<::std::string::String>,
    pub(crate) plan_id: ::std::option::Option<::std::string::String>,
    pub(crate) ignore_errors: ::std::option::Option<bool>,
}
impl DeleteProvisionedProductPlanInputBuilder {
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn accept_language(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.accept_language = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn set_accept_language(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.accept_language = input;
        self
    }
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn get_accept_language(&self) -> &::std::option::Option<::std::string::String> {
        &self.accept_language
    }
    /// <p>The plan identifier.</p>
    /// This field is required.
    pub fn plan_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.plan_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The plan identifier.</p>
    pub fn set_plan_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.plan_id = input;
        self
    }
    /// <p>The plan identifier.</p>
    pub fn get_plan_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.plan_id
    }
    /// <p>If set to true, Service Catalog stops managing the specified provisioned product even if it cannot delete the underlying resources.</p>
    pub fn ignore_errors(mut self, input: bool) -> Self {
        self.ignore_errors = ::std::option::Option::Some(input);
        self
    }
    /// <p>If set to true, Service Catalog stops managing the specified provisioned product even if it cannot delete the underlying resources.</p>
    pub fn set_ignore_errors(mut self, input: ::std::option::Option<bool>) -> Self {
        self.ignore_errors = input;
        self
    }
    /// <p>If set to true, Service Catalog stops managing the specified provisioned product even if it cannot delete the underlying resources.</p>
    pub fn get_ignore_errors(&self) -> &::std::option::Option<bool> {
        &self.ignore_errors
    }
    /// Consumes the builder and constructs a [`DeleteProvisionedProductPlanInput`](crate::operation::delete_provisioned_product_plan::DeleteProvisionedProductPlanInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_provisioned_product_plan::DeleteProvisionedProductPlanInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_provisioned_product_plan::DeleteProvisionedProductPlanInput {
            accept_language: self.accept_language,
            plan_id: self.plan_id,
            ignore_errors: self.ignore_errors,
        })
    }
}
