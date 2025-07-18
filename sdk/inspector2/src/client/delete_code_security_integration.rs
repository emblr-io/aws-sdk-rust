// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`DeleteCodeSecurityIntegration`](crate::operation::delete_code_security_integration::builders::DeleteCodeSecurityIntegrationFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`integration_arn(impl Into<String>)`](crate::operation::delete_code_security_integration::builders::DeleteCodeSecurityIntegrationFluentBuilder::integration_arn) / [`set_integration_arn(Option<String>)`](crate::operation::delete_code_security_integration::builders::DeleteCodeSecurityIntegrationFluentBuilder::set_integration_arn):<br>required: **true**<br><p>The Amazon Resource Name (ARN) of the code security integration to delete.</p><br>
    /// - On success, responds with [`DeleteCodeSecurityIntegrationOutput`](crate::operation::delete_code_security_integration::DeleteCodeSecurityIntegrationOutput) with field(s):
    ///   - [`integration_arn(Option<String>)`](crate::operation::delete_code_security_integration::DeleteCodeSecurityIntegrationOutput::integration_arn): <p>The Amazon Resource Name (ARN) of the deleted code security integration.</p>
    /// - On failure, responds with [`SdkError<DeleteCodeSecurityIntegrationError>`](crate::operation::delete_code_security_integration::DeleteCodeSecurityIntegrationError)
    pub fn delete_code_security_integration(
        &self,
    ) -> crate::operation::delete_code_security_integration::builders::DeleteCodeSecurityIntegrationFluentBuilder {
        crate::operation::delete_code_security_integration::builders::DeleteCodeSecurityIntegrationFluentBuilder::new(self.handle.clone())
    }
}
