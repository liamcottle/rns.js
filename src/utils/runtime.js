class Runtime {

    /**
     * Determine if we are running in a web browser, otherwise we are probably running from NodeJS
     * @returns {boolean}
     */
    static isBrowser() {
        return typeof(window) !== 'undefined';
    }

}

export default Runtime;
