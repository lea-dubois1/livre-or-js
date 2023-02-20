const inscriptionButton = document.getElementById('switchInscription');
const connexionButton = document.getElementById('switchConnexion');




//Si on click sur le boutton inscription sur la home page
inscriptionButton.addEventListener('click', ()=>{

    //call the php inscription file
    fetch('inscription.php')
    .then((promise)=>{
        return promise.text();
    })
    .then((content)=>{
        const form = document.getElementById('form');
        form.innerHTML = content;
        const registerForm = document.getElementById('signupForm');

        registerForm.addEventListener('submit', (e) => {

            e.preventDefault();

            const errorPassDiv = document.getElementById('errorPass');
            errorPassDiv.innerHTML = "";
            const paraErrorPassMatch = document.createElement("p");
            const paraErrorPassLong = document.createElement("p");
        
            const errorEmailDiv = document.getElementById('errorEmail');
            errorEmailDiv.innerHTML = "";
            const paraErrorEmailLet = document.createElement("p");
            const paraErrorEmailExist = document.createElement("p");
        
            const errorNomDiv = document.getElementById('errorNom');
            errorNomDiv.innerHTML = "";
            const paraErrorNames = document.createElement("p");
            
            const okRegDiv = document.getElementById('okReg');
            okRegDiv.innerHTML = "";
            const paraOkReg = document.createElement("p");

            const formData = new FormData(registerForm);

            console.log(formData)

            formData.forEach((value, key) => {
                console.log(key + ':' + value);
            });

            fetch("inscriptionBack.php", {
                method: "POST",
                body: formData,
            })
            .then(response => {
                return response.json();
            })
            .then(message => {
                const dataJSON = message;
                console.log(dataJSON);

                if(dataJSON['errorPassMatch']) {
                    paraErrorPassMatch.textContent = dataJSON['errorPassMatch'];
                    errorPassDiv.appendChild(paraErrorPassMatch);
                }
                if(dataJSON['errorPassLong']) {
                    paraErrorPassLong.textContent = dataJSON['errorPassLong'];
                    errorPassDiv.appendChild(paraErrorPassLong);
                }
                if(dataJSON['errorEmailLet']) {
                    paraErrorEmailLet.textContent = dataJSON['errorEmailLet'];
                    errorEmailDiv.appendChild(paraErrorEmailLet);
                }
                if(dataJSON['errorNames']) {
                    paraErrorNames.textContent = dataJSON['errorNames'];
                    errorNomDiv.appendChild(paraErrorNames);
                }
                if(dataJSON['errorEmailExist']) {
                    paraErrorEmailExist.textContent = dataJSON['errorEmailExist'];
                    errorEmailDiv.appendChild(paraErrorEmailExist);
                }
                if(dataJSON['okReg']) {
                    paraOkReg.textContent = dataJSON['okReg'];
                    okRegDiv.appendChild(paraOkReg);
                }

            })
            .catch(error => alert("Erreur : " + error));
        
        })
    })

})




connexionButton.addEventListener('click', ()=>{


    fetch('connexion.php')
    .then((promise)=>{
        return promise.text();
    })
    .then((content)=>{
        const form = document.getElementById('form');
        form.innerHTML = content;
        const signinForm = document.getElementById('signinForm');

        signinForm.addEventListener('submit', (e) => {

            e.preventDefault();
            const formData = new FormData(signinForm);

            fetch("connexionBack.php", {
                method: "POST",
                body: formData,
            })
            .then(response => {
                return response.json();
            })
            .then(message => {
                const dataJSON = message;
                console.log(dataJSON);

                if(dataJSON['errorPass']) {
                    const errorPassDiv = document.getElementById('errorPass');
                    const paraErrorPass = document.createElement("p");
                    paraErrorPass.textContent = dataJSON['errorPass'];
                    errorPassDiv.appendChild(paraErrorPass);
                }
                if(dataJSON['errorEmail']) {
                    const errorEmailDiv = document.getElementById('errorEmail');
                    const paraErrorEmail = document.createElement("p");
                    paraErrorEmail.textContent = dataJSON['errorEmail'];
                    errorEmailDiv.appendChild(paraErrorEmail);
                }
                if(dataJSON['okConn']) {
                    const okConn = document.getElementById('okConn');
                    const paraokConn = document.createElement("p");
                    paraokConn.textContent = dataJSON['okConn'];
                    okConn.appendChild(paraokConn);
                    // document.location.href="pageBonjour.php"; 
                }
            })
            .catch(error => alert("Error : " + error));
        })
    })
})