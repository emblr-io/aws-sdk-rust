// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`UpdateAccountAssociation`](crate::operation::update_account_association::builders::UpdateAccountAssociationFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`account_association_id(impl Into<String>)`](crate::operation::update_account_association::builders::UpdateAccountAssociationFluentBuilder::account_association_id) / [`set_account_association_id(Option<String>)`](crate::operation::update_account_association::builders::UpdateAccountAssociationFluentBuilder::set_account_association_id):<br>required: **true**<br><p>The unique identifier of the account association to update.</p><br>
    ///   - [`name(impl Into<String>)`](crate::operation::update_account_association::builders::UpdateAccountAssociationFluentBuilder::name) / [`set_name(Option<String>)`](crate::operation::update_account_association::builders::UpdateAccountAssociationFluentBuilder::set_name):<br>required: **false**<br><p>The new name to assign to the account association.</p><br>
    ///   - [`description(impl Into<String>)`](crate::operation::update_account_association::builders::UpdateAccountAssociationFluentBuilder::description) / [`set_description(Option<String>)`](crate::operation::update_account_association::builders::UpdateAccountAssociationFluentBuilder::set_description):<br>required: **false**<br><p>The new description to assign to the account association.</p><br>
    /// - On success, responds with [`UpdateAccountAssociationOutput`](crate::operation::update_account_association::UpdateAccountAssociationOutput)
    /// - On failure, responds with [`SdkError<UpdateAccountAssociationError>`](crate::operation::update_account_association::UpdateAccountAssociationError)
    pub fn update_account_association(&self) -> crate::operation::update_account_association::builders::UpdateAccountAssociationFluentBuilder {
        crate::operation::update_account_association::builders::UpdateAccountAssociationFluentBuilder::new(self.handle.clone())
    }
}
