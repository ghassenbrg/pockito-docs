Based on the provided openapi.json file in pockito-docs, generate Angular service classes for each API controller:

Check existence: For each controller in the OpenAPI spec, verify whether a corresponding Angular service file already exists in the codebase.

Create if missing: If the service does not exist, create a new Angular service file with:

Strongly typed request/response models (generated from the OpenAPI schema).

Methods for each endpoint, using HttpClient.

Proper Observable<T> return types.

JSDoc or TypeDoc comments for clarity.

Update if exists: If the service file already exists, update it to match the OpenAPI definition by:

Adding missing methods.

Updating method signatures, request/response types, and endpoint URLs if they changed.

Preserving any custom logic or comments already in the file.

Consistency: Ensure naming conventions, method signatures, and file structure are consistent across all services.

Output: Provide the updated or newly created service files ready to be placed in the Angular project under src/app/services/.

⚡️ Important: Do not regenerate everything blindly. Only create or update what is necessary based on openapi.json

